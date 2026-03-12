/**
 * StrongSales Entry Analytics Dashboard
 *
 * A complete entry/visit analytics dashboard for Zoezi gyms.
 * Powered by StrongSales - https://strongsales.se
 *
 * Database-backed architecture: entries are synced from Zoezi to Supabase,
 * analytics are computed via PostgreSQL functions.
 */

'use strict';

require('./dateextensions.js');

const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 5000;

// Environment variables
const SUPABASE_URL = 'https://kzdrezwyvgwttnwvbild.supabase.co';
const SUPABASE_API_KEY = process.env.SUPABASE_API_KEY;
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'strongsales2024';
const ADMIN_KEY = process.env.ADMIN_KEY || crypto.randomBytes(24).toString('hex');
const EMBED_SECRET = process.env.EMBED_SECRET || crypto.randomBytes(32).toString('hex');

// Supabase client (singleton)
let _supabase = null;
function getSupabase() {
  if (!SUPABASE_API_KEY) {
    throw new Error('SUPABASE_API_KEY is required');
  }
  if (!_supabase) {
    _supabase = createClient(SUPABASE_URL, SUPABASE_API_KEY);
  }
  return _supabase;
}

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session configuration
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: 'strongsales_entry_session',
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'lax'
  }
}));

// Auth middleware
function isAuthenticated(req, res, next) {
  if (req.session && req.session.authenticated) {
    return next();
  }
  res.status(401).json({ error: 'Not authenticated' });
}

function isAdmin(req, res, next) {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey && timingSafeEqual(adminKey, ADMIN_KEY)) {
    return next();
  }
  res.status(403).json({ error: 'Admin access required' });
}

// Timing-safe string comparison
function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
  } catch {
    return false;
  }
}

// Token generation and verification
function generateEmbedToken(clubId) {
  const timestamp = Date.now().toString();
  const payload = `${clubId}.${timestamp}`;
  const signature = crypto
    .createHmac('sha256', EMBED_SECRET)
    .update(payload)
    .digest('base64url');

  return `${Buffer.from(clubId.toString()).toString('base64url')}.${Buffer.from(timestamp).toString('base64url')}.${signature}`;
}

function verifyEmbedToken(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return { valid: false, error: 'Invalid token format' };
    }

    const clubId = Buffer.from(parts[0], 'base64url').toString();
    const timestamp = Buffer.from(parts[1], 'base64url').toString();
    const providedSignature = parts[2];

    const expectedSignature = crypto
      .createHmac('sha256', EMBED_SECRET)
      .update(`${clubId}.${timestamp}`)
      .digest('base64url');

    const isValid = crypto.timingSafeEqual(
      Buffer.from(providedSignature),
      Buffer.from(expectedSignature)
    );

    if (!isValid) {
      return { valid: false, error: 'Invalid signature' };
    }

    // Check token age (1 year max)
    const tokenAge = Date.now() - parseInt(timestamp);
    const oneYear = 365 * 24 * 60 * 60 * 1000;
    if (tokenAge > oneYear) {
      return { valid: false, error: 'Token expired' };
    }

    return { valid: true, clubId };
  } catch (error) {
    return { valid: false, error: 'Token verification failed' };
  }
}

// Zoezi API helper for GET requests
async function zoeziFetch(domain, apiKey, endpoint, maxRetries = 3) {
  const url = `https://${domain}${endpoint}`;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const response = await fetch(url, {
        headers: {
          'Authorization': apiKey,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        throw new Error(`Zoezi API error: ${response.status} ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error(`Attempt ${attempt}/${maxRetries} failed for ${endpoint}:`, error.message);
      if (attempt === maxRetries) throw error;
      await new Promise(r => setTimeout(r, attempt * 2000));
    }
  }
}

// ========== SYNC SYSTEM ==========

// Generate array of date strings between from and to (inclusive)
function getDateRange(fromDate, toDate) {
  const dates = [];
  const current = new Date(fromDate + 'T00:00:00');
  const end = new Date(toDate + 'T00:00:00');
  while (current <= end) {
    dates.push(current.toISOString().split('T')[0]);
    current.setDate(current.getDate() + 1);
  }
  return dates;
}

// Determine if a date in Stockholm is CET (+01) or CEST (+02)
// EU DST: last Sunday of March → last Sunday of October
function getStockholmOffset(year, month, day) {
  // Last Sunday of March
  const marchLast = new Date(year, 2, 31);
  marchLast.setDate(31 - marchLast.getDay());
  // Last Sunday of October
  const octLast = new Date(year, 9, 31);
  octLast.setDate(31 - octLast.getDay());

  const d = new Date(year, month - 1, day);
  return (d >= marchLast && d < octLast) ? '+02:00' : '+01:00';
}

// Get today and yesterday as YYYY-MM-DD in Stockholm timezone
function getStockholmDates() {
  const now = new Date();
  const fmt = new Intl.DateTimeFormat('sv-SE', { timeZone: 'Europe/Stockholm' });
  const todayStr = fmt.format(now);
  const yesterday = new Date(now.getTime() - 86400000);
  const yesterdayStr = fmt.format(yesterday);
  return { todayStr, yesterdayStr };
}

// Parse Zoezi local time string "YYYY-MM-DD HH:MM:SS" into components
function parseZoeziEntryTime(entryTimeStr) {
  // Zoezi returns local time (Europe/Stockholm), not UTC
  const parts = entryTimeStr.split(' ');
  const datePart = parts[0]; // "YYYY-MM-DD"
  const timePart = parts[1] || '00:00:00'; // "HH:MM:SS"

  const [year, month, day] = datePart.split('-').map(Number);
  const [hour] = timePart.split(':').map(Number);

  // Compute day of week from the date
  const d = new Date(year, month - 1, day);
  const dow = d.getDay(); // 0=Sunday, 6=Saturday

  // Compute correct UTC offset for this date (CET +01 or CEST +02)
  const offset = getStockholmOffset(year, month, day);

  return {
    entry_date: datePart,
    entry_hour: hour,
    entry_dow: dow,
    entry_time_tz: `${datePart} ${timePart}${offset}` // timestamptz-safe string
  };
}

// Sync entries from Zoezi to Supabase for missing/stale days
async function ensureSync(supabase, club, fromDate, toDate) {
  const clubId = club.Club_Zoezi_ID;
  const domain = club.Zoezi_Domain;
  const apiKey = club.Zoezi_Api_Key;

  const allDates = getDateRange(fromDate, toDate);
  if (allDates.length === 0) return;

  // 1. Check which dates are already synced
  const { data: syncedDays, error: syncErr } = await supabase
    .from('entry_sync_days')
    .select('sync_date, is_final, last_synced_at')
    .eq('club_id', clubId)
    .gte('sync_date', fromDate)
    .lte('sync_date', toDate);

  if (syncErr) {
    console.error('Error checking sync days:', syncErr);
    throw syncErr;
  }

  const syncMap = {};
  (syncedDays || []).forEach(s => {
    syncMap[s.sync_date] = s;
  });

  // 2. Determine which dates need syncing (using Stockholm local time)
  const now = new Date();
  const { todayStr, yesterdayStr } = getStockholmDates();

  const datesToSync = [];
  for (const dateStr of allDates) {
    const existing = syncMap[dateStr];
    if (!existing) {
      // Never synced
      datesToSync.push(dateStr);
    } else if (!existing.is_final && (dateStr === todayStr || dateStr === yesterdayStr)) {
      // Recent day, check staleness (>15 min)
      const lastSynced = new Date(existing.last_synced_at);
      const ageMs = now - lastSynced;
      if (ageMs > 15 * 60 * 1000) {
        datesToSync.push(dateStr);
      }
    }
    // If is_final=true, skip (fully synced historical day)
  }

  if (datesToSync.length === 0) {
    // Also check if doors/sites need refresh
    await refreshMetadataIfNeeded(supabase, club);
    return;
  }

  console.log(`[sync] Club ${clubId}: syncing ${datesToSync.length} day(s) out of ${allDates.length}`);

  // 3. Fetch and insert day-by-day
  for (const dateStr of datesToSync) {
    try {
      const entries = await fetchZoeziEntriesForDay(domain, apiKey, dateStr);

      // Upsert entries in batches (safe: no delete, just upsert on conflict)
      let insertOk = true;
      if (entries.length > 0) {
        const rows = entries.map(e => {
          const parsed = parseZoeziEntryTime(e.entryTime);
          return {
            club_id: clubId,
            zoezi_entry_id: e.id,
            entry_time: parsed.entry_time_tz,
            entry_date: parsed.entry_date,
            entry_hour: parsed.entry_hour,
            entry_dow: parsed.entry_dow,
            success: e.success !== false,
            user_id: e.user_id || null,
            member_id: e.member_id || null,
            door_id: e.door != null ? String(e.door) : null,
            reason: e.reason || null,
            card_name: e.cardName || null,
            site_ids: (e.sites || []).map(Number).filter(n => !isNaN(n))
          };
        });

        for (let i = 0; i < rows.length; i += 1000) {
          const batch = rows.slice(i, i + 1000);
          const { error: insertErr } = await supabase
            .from('entry_events')
            .upsert(batch, { onConflict: 'club_id,zoezi_entry_id' });

          if (insertErr) {
            console.error(`[sync] Insert error for ${clubId}/${dateStr} batch ${i}:`, insertErr);
            insertOk = false;
          }
        }
      }

      // Only mark as synced if inserts succeeded
      if (insertOk) {
        const isFinal = dateStr < yesterdayStr; // Days before yesterday are final
        const { error: syncUpsertErr } = await supabase
          .from('entry_sync_days')
          .upsert({
            club_id: clubId,
            sync_date: dateStr,
            is_final: isFinal,
            entry_count: entries.length,
            last_synced_at: new Date().toISOString()
          }, { onConflict: 'club_id,sync_date' });

        if (syncUpsertErr) {
          console.error(`[sync] Sync tracking error for ${clubId}/${dateStr}:`, syncUpsertErr);
        }
        console.log(`[sync] ${clubId}/${dateStr}: ${entries.length} entries (final=${isFinal})`);
      } else {
        console.error(`[sync] ${clubId}/${dateStr}: insert failed, NOT marking as synced`);
      }
    } catch (err) {
      console.error(`[sync] Failed to sync ${clubId}/${dateStr}:`, err.message);
      // Continue with other dates
    }
  }

  // 4. Refresh metadata if needed
  await refreshMetadataIfNeeded(supabase, club);
}

// Fetch entries for a single day from Zoezi
async function fetchZoeziEntriesForDay(domain, apiKey, dateStr) {
  const url = `https://${domain}/api/entry/get?fromDate=${dateStr}&toDate=${dateStr}&idOnly=True`;

  console.log(`[entry/get] Fetching ${domain} for ${dateStr}`);
  const startTime = Date.now();

  const response = await fetch(url, {
    headers: {
      'Authorization': apiKey,
      'Content-Type': 'application/json'
    }
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`entry/get API error: ${response.status} - ${errorText}`);
  }

  const entries = await response.json();
  const duration = Date.now() - startTime;
  console.log(`[entry/get] ${domain}/${dateStr}: ${entries?.length || 0} entries in ${duration}ms`);

  return entries || [];
}

// Refresh door and site metadata if stale (>6 hours)
async function refreshMetadataIfNeeded(supabase, club) {
  const clubId = club.Club_Zoezi_ID;
  const domain = club.Zoezi_Domain;
  const apiKey = club.Zoezi_Api_Key;

  // Check last update time for doors
  const { data: lastDoor } = await supabase
    .from('club_doors')
    .select('updated_at')
    .eq('club_id', clubId)
    .order('updated_at', { ascending: false })
    .limit(1);

  const sixHoursAgo = new Date(Date.now() - 6 * 60 * 60 * 1000);
  const doorsStale = !lastDoor || lastDoor.length === 0 || new Date(lastDoor[0].updated_at) < sixHoursAgo;

  if (doorsStale) {
    try {
      const [resources, sitesData] = await Promise.all([
        zoeziFetch(domain, apiKey, '/api/resource/get').catch(() => null),
        zoeziFetch(domain, apiKey, '/api/site/get/all').catch(() => null)
      ]);

      if (resources && resources.length > 0) {
        const doorRows = resources.map(r => ({
          club_id: clubId,
          door_id: String(r.id),
          door_name: r.name,
          updated_at: new Date().toISOString()
        }));
        await supabase
          .from('club_doors')
          .upsert(doorRows, { onConflict: 'club_id,door_id' });
      }

      if (sitesData && sitesData.length > 0) {
        const siteRows = sitesData.map(s => ({
          club_id: clubId,
          site_id: s.id,
          site_name: s.name,
          updated_at: new Date().toISOString()
        }));
        await supabase
          .from('club_sites')
          .upsert(siteRows, { onConflict: 'club_id,site_id' });
      }

      console.log(`[meta] Refreshed doors/sites for ${clubId}`);
    } catch (e) {
      console.log(`[meta] Could not refresh metadata for ${clubId}:`, e.message);
    }
  }
}

// Parse filter params from query string
function parseFilterParams(query) {
  const params = {
    fromDate: query.fromDate,
    toDate: query.toDate,
    doors: query.doors === '_none' ? ['__impossible__'] : (query.doors ? query.doors.split(',').filter(Boolean) : null),
    cards: query.cards === '_none' ? ['__impossible__'] : (query.cards ? query.cards.split(',').filter(Boolean) : null),
    sites: query.sites === '_none' ? [-1] : (query.sites ? query.sites.split(',').map(Number).filter(n => !isNaN(n)) : null),
    status: query.status || 'all',
    uniqueVisits: query.uniqueVisits === 'true',
    page: parseInt(query.page) || 1,
    limit: Math.min(parseInt(query.limit) || 20, 100)
  };

  // Convert empty arrays to null (meaning "no filter")
  if (params.doors && params.doors.length === 0) params.doors = null;
  if (params.cards && params.cards.length === 0) params.cards = null;
  if (params.sites && params.sites.length === 0) params.sites = null;

  return params;
}

// Core analytics handler (shared between authenticated and embed routes)
async function handleAnalytics(club, filters, supabase) {
  const clubId = club.Club_Zoezi_ID;

  // 1. Ensure data is synced
  await ensureSync(supabase, club, filters.fromDate, filters.toDate);

  // 2. Call analytics RPC
  const { data: analyticsData, error: analyticsErr } = await supabase.rpc('get_entry_analytics', {
    p_club_id: clubId,
    p_from_date: filters.fromDate,
    p_to_date: filters.toDate,
    p_doors: filters.doors,
    p_cards: filters.cards,
    p_sites: filters.sites,
    p_status: filters.status,
    p_unique_visits: filters.uniqueVisits
  });

  if (analyticsErr) {
    console.error('Analytics RPC error:', analyticsErr);
    throw new Error('Failed to compute analytics: ' + analyticsErr.message);
  }

  // 3. Call paginated entries RPC
  const { data: pageData, error: pageErr } = await supabase.rpc('get_entry_page', {
    p_club_id: clubId,
    p_from_date: filters.fromDate,
    p_to_date: filters.toDate,
    p_doors: filters.doors,
    p_cards: filters.cards,
    p_sites: filters.sites,
    p_status: filters.status,
    p_page: filters.page,
    p_limit: filters.limit
  });

  if (pageErr) {
    console.error('Page RPC error:', pageErr);
    throw new Error('Failed to fetch entries page: ' + pageErr.message);
  }

  // 4. Fetch sites from cache
  const { data: sites } = await supabase
    .from('club_sites')
    .select('site_id, site_name')
    .eq('club_id', clubId);

  const siteList = (sites || []).map(s => ({ id: s.site_id, name: s.site_name }));

  // 5. Build response
  const response = {
    ...analyticsData,
    entries: pageData.entries,
    entriesIncluded: true,
    entriesPage: pageData,
    sites: siteList,
    club: {
      id: club.Club_Zoezi_ID,
      name: club.Club_name,
      domain: club.Zoezi_Domain
    },
    dateRange: {
      fromDate: filters.fromDate,
      toDate: filters.toDate
    }
  };

  return response;
}

// ========== ROUTES ==========

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', service: 'entry-analytics' });
});

// Login page
app.get('/login', (req, res) => {
  if (req.session && req.session.authenticated) {
    return res.redirect('/');
  }
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Login - Entry Analytics</title>
      <script src="https://cdn.tailwindcss.com"></script>
      <script>
        tailwind.config = {
          theme: {
            extend: {
              colors: {
                strongsales: {
                  300: '#AFACFB',
                  500: '#8b5cf6',
                  700: '#6d28d9'
                }
              }
            }
          }
        }
      </script>
      <style>
        .gradient-bg { background: linear-gradient(135deg, #AFACFB 0%, #8b5cf6 50%, #6d28d9 100%); }
      </style>
    </head>
    <body class="min-h-screen gradient-bg flex items-center justify-center p-4">
      <div class="bg-white rounded-2xl shadow-2xl p-8 w-full max-w-md">
        <div class="text-center mb-8">
          <img src="/Strongsales%20logo%20black%20%26%20purple%20Transparent.png" alt="StrongSales" class="h-12 mx-auto mb-4">
          <h1 class="text-2xl font-bold text-gray-900">Entry Analytics</h1>
          <p class="text-gray-500 mt-2">Sign in to access the dashboard</p>
        </div>
        <form action="/login" method="POST">
          <div class="mb-6">
            <label class="block text-sm font-medium text-gray-700 mb-2">Password</label>
            <input type="password" name="password" required autofocus
              class="w-full px-4 py-3 border border-gray-300 rounded-xl focus:ring-2 focus:ring-strongsales-300 focus:border-transparent outline-none transition-all"
              placeholder="Enter password">
          </div>
          <button type="submit" class="w-full py-3 px-4 gradient-bg text-white font-semibold rounded-xl hover:opacity-90 transition-all">
            Sign In
          </button>
        </form>
      </div>
    </body>
    </html>
  `);
});

// Login POST
app.post('/login', (req, res) => {
  const { password } = req.body;
  if (password && timingSafeEqual(password, ADMIN_PASSWORD)) {
    req.session.authenticated = true;
    res.redirect('/');
  } else {
    res.redirect('/login?error=1');
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// Get all gyms/clubs
app.get('/api/gyms', isAuthenticated, async (req, res) => {
  try {
    const supabase = getSupabase();
    const { data, error } = await supabase
      .from('Clubs')
      .select('Club_Zoezi_ID, Club_name, Zoezi_Domain')
      .order('Club_name');

    if (error) throw error;

    res.json(data || []);
  } catch (error) {
    console.error('Error fetching gyms:', error);
    res.status(500).json({ error: 'Failed to fetch gyms' });
  }
});

// Get entry analytics for a club
app.get('/api/analytics/:clubId', isAuthenticated, async (req, res) => {
  req.setTimeout(120000);
  try {
    const { clubId } = req.params;
    const filters = parseFilterParams(req.query);

    if (!filters.fromDate || !filters.toDate) {
      return res.status(400).json({ error: 'fromDate and toDate are required' });
    }

    const supabase = getSupabase();
    const { data: club, error: clubError } = await supabase
      .from('Clubs')
      .select('*')
      .eq('Club_Zoezi_ID', clubId)
      .single();

    if (clubError || !club) {
      return res.status(404).json({ error: 'Club not found' });
    }

    const response = await handleAnalytics(club, filters, supabase);
    res.json(response);
  } catch (error) {
    console.error('Error fetching analytics:', error);
    res.status(500).json({ error: 'Failed to fetch analytics', message: error.message });
  }
});

// CSV export for a club
app.get('/api/analytics/:clubId/export.csv', isAuthenticated, async (req, res) => {
  req.setTimeout(120000);
  try {
    const { clubId } = req.params;
    const filters = parseFilterParams(req.query);

    if (!filters.fromDate || !filters.toDate) {
      return res.status(400).json({ error: 'fromDate and toDate are required' });
    }

    const supabase = getSupabase();
    const { data: club, error: clubError } = await supabase
      .from('Clubs')
      .select('*')
      .eq('Club_Zoezi_ID', clubId)
      .single();

    if (clubError || !club) {
      return res.status(404).json({ error: 'Club not found' });
    }

    // Ensure data is synced
    await ensureSync(supabase, club, filters.fromDate, filters.toDate);

    // Stream CSV from DB - fetch all matching entries (no pagination)
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="entry-analytics-${club.Club_name}-${filters.fromDate}-${filters.toDate}.csv"`);

    // Write CSV header
    res.write('Time,User ID,Member,Door,Card Type,Status,Reason\n');

    // Fetch entries in pages to avoid OOM
    let page = 1;
    const pageSize = 5000;
    let hasMore = true;

    while (hasMore) {
      const { data: pageData, error: pageErr } = await supabase.rpc('get_entry_page', {
        p_club_id: clubId,
        p_from_date: filters.fromDate,
        p_to_date: filters.toDate,
        p_doors: filters.doors,
        p_cards: filters.cards,
        p_sites: filters.sites,
        p_status: filters.status,
        p_page: page,
        p_limit: pageSize
      });

      if (pageErr) {
        console.error('CSV export page error:', pageErr);
        break;
      }

      const entries = pageData.entries || [];
      for (const e of entries) {
        const row = [
          e.entryTime || '',
          e.userId || '',
          e.memberName || '',
          e.doorName || '',
          e.cardName || '',
          e.success ? 'Success' : 'Failed',
          e.reason || ''
        ].map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(',');
        res.write(row + '\n');
      }

      hasMore = page < pageData.totalPages;
      page++;
    }

    res.end();
  } catch (error) {
    console.error('CSV export error:', error);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Failed to export CSV', message: error.message });
    } else {
      res.end();
    }
  }
});

// Verify embed token
app.get('/api/verify-token', (req, res) => {
  const { token } = req.query;
  if (!token) {
    return res.status(400).json({ valid: false, error: 'Token required' });
  }
  const result = verifyEmbedToken(token);
  res.json(result);
});

// Embed analytics endpoint (token-authenticated)
app.get('/api/embed/analytics', async (req, res) => {
  req.setTimeout(120000);
  try {
    const { token } = req.query;

    if (!token) {
      return res.status(401).json({ error: 'Token required' });
    }

    const verification = verifyEmbedToken(token);
    if (!verification.valid) {
      return res.status(401).json({ error: verification.error });
    }

    const filters = parseFilterParams(req.query);

    if (!filters.fromDate || !filters.toDate) {
      return res.status(400).json({ error: 'fromDate and toDate are required' });
    }

    const clubId = verification.clubId;

    const supabase = getSupabase();
    const { data: club, error: clubError } = await supabase
      .from('Clubs')
      .select('*')
      .eq('Club_Zoezi_ID', clubId)
      .single();

    if (clubError || !club) {
      return res.status(404).json({ error: 'Club not found' });
    }

    const response = await handleAnalytics(club, filters, supabase);
    res.json(response);
  } catch (error) {
    console.error('Embed analytics error:', error);
    res.status(500).json({ error: 'Failed to fetch analytics', message: error.message });
  }
});

// Embed CSV export (token-authenticated)
app.get('/api/embed/export.csv', async (req, res) => {
  req.setTimeout(120000);
  try {
    const { token } = req.query;

    if (!token) {
      return res.status(401).json({ error: 'Token required' });
    }

    const verification = verifyEmbedToken(token);
    if (!verification.valid) {
      return res.status(401).json({ error: verification.error });
    }

    const filters = parseFilterParams(req.query);

    if (!filters.fromDate || !filters.toDate) {
      return res.status(400).json({ error: 'fromDate and toDate are required' });
    }

    const clubId = verification.clubId;

    const supabase = getSupabase();
    const { data: club, error: clubError } = await supabase
      .from('Clubs')
      .select('*')
      .eq('Club_Zoezi_ID', clubId)
      .single();

    if (clubError || !club) {
      return res.status(404).json({ error: 'Club not found' });
    }

    await ensureSync(supabase, club, filters.fromDate, filters.toDate);

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="entry-analytics-${club.Club_name}-${filters.fromDate}-${filters.toDate}.csv"`);

    res.write('Time,User ID,Member,Door,Card Type,Status,Reason\n');

    let page = 1;
    const pageSize = 5000;
    let hasMore = true;

    while (hasMore) {
      const { data: pageData, error: pageErr } = await supabase.rpc('get_entry_page', {
        p_club_id: clubId,
        p_from_date: filters.fromDate,
        p_to_date: filters.toDate,
        p_doors: filters.doors,
        p_cards: filters.cards,
        p_sites: filters.sites,
        p_status: filters.status,
        p_page: page,
        p_limit: pageSize
      });

      if (pageErr) break;

      const entries = pageData.entries || [];
      for (const e of entries) {
        const row = [
          e.entryTime || '',
          e.userId || '',
          e.memberName || '',
          e.doorName || '',
          e.cardName || '',
          e.success ? 'Success' : 'Failed',
          e.reason || ''
        ].map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(',');
        res.write(row + '\n');
      }

      hasMore = page < pageData.totalPages;
      page++;
    }

    res.end();
  } catch (error) {
    console.error('Embed CSV export error:', error);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Failed to export CSV', message: error.message });
    } else {
      res.end();
    }
  }
});

// Admin: Generate embed token
app.post('/api/admin/embed-token', isAdmin, async (req, res) => {
  try {
    const { clubId } = req.body;

    if (!clubId) {
      return res.status(400).json({ error: 'clubId is required' });
    }

    const supabase = getSupabase();
    const { data: club, error } = await supabase
      .from('Clubs')
      .select('Club_Zoezi_ID, Club_name')
      .eq('Club_Zoezi_ID', clubId)
      .single();

    if (error || !club) {
      return res.status(404).json({ error: 'Club not found' });
    }

    const token = generateEmbedToken(clubId);
    const baseUrl = `${req.protocol}://${req.get('host')}`;

    res.json({
      token,
      clubId: club.Club_Zoezi_ID,
      clubName: club.Club_name,
      embedUrl: `${baseUrl}/?token=${token}&hideHeader=true`
    });
  } catch (error) {
    console.error('Token generation error:', error);
    res.status(500).json({ error: 'Failed to generate token' });
  }
});

// Admin: Generate all embed tokens
app.get('/api/admin/embed-tokens', isAdmin, async (req, res) => {
  try {
    const supabase = getSupabase();
    const { data: clubs, error } = await supabase
      .from('Clubs')
      .select('Club_Zoezi_ID, Club_name')
      .order('Club_name');

    if (error) throw error;

    const baseUrl = `${req.protocol}://${req.get('host')}`;

    const tokens = clubs.map(club => {
      const token = generateEmbedToken(club.Club_Zoezi_ID);
      return {
        token,
        clubId: club.Club_Zoezi_ID,
        clubName: club.Club_name,
        embedUrl: `${baseUrl}/?token=${token}&hideHeader=true`
      };
    });

    res.json(tokens);
  } catch (error) {
    console.error('Token generation error:', error);
    res.status(500).json({ error: 'Failed to generate tokens' });
  }
});

// Serve main app - MUST be before express.static to enforce auth
app.get('/', (req, res, next) => {
  // Check for embed token in URL
  const token = req.query.token;
  if (token) {
    return next(); // Let static middleware handle it
  }

  // Otherwise require authentication
  if (!req.session || !req.session.authenticated) {
    return res.redirect('/login');
  }
  next();
});

// Static files - AFTER root route protection
app.use(express.static('public'));

// Start server with extended timeouts for slow Zoezi API responses
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   StrongSales Entry Analytics Dashboard                       ║
║   ─────────────────────────────────────                       ║
║   Server running on port ${PORT}                                 ║
║   http://localhost:${PORT}                                       ║
║   Database-backed architecture (Supabase)                     ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
  `);
});

// Allow up to 2 minutes for slow Zoezi API fetches (Replit proxy can kill idle connections)
server.timeout = 120000;
server.keepAliveTimeout = 120000;
server.headersTimeout = 125000;
