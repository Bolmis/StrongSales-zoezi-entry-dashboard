/**
 * StrongSales Entry Analytics Dashboard
 *
 * A complete entry/visit analytics dashboard for Zoezi gyms.
 * Powered by StrongSales - https://strongsales.se
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

// Supabase client
function getSupabase() {
  if (!SUPABASE_API_KEY) {
    throw new Error('SUPABASE_API_KEY is required');
  }
  return createClient(SUPABASE_URL, SUPABASE_API_KEY);
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

// Zoezi API helper
async function zoeziFetch(domain, apiKey, endpoint) {
  const url = `https://${domain}${endpoint}`;
  const response = await fetch(url, {
    headers: {
      'Authorization': `Basic ${apiKey}`,
      'Content-Type': 'application/json'
    }
  });

  if (!response.ok) {
    throw new Error(`Zoezi API error: ${response.status} ${response.statusText}`);
  }

  return response.json();
}

// Process entry data into analytics
function processEntryAnalytics(entries, doors = []) {
  if (!entries || entries.length === 0) {
    return {
      summary: {
        totalEntries: 0,
        successfulEntries: 0,
        failedEntries: 0,
        successRate: 0,
        uniqueVisitors: 0,
        avgEntriesPerDay: 0,
        peakHour: null,
        peakDay: null
      },
      byHour: [],
      byDay: [],
      byDoor: [],
      byCardType: [],
      dailyTrend: [],
      topVisitors: [],
      failedReasons: [],
      rawEntries: entries
    };
  }

  // Create door lookup
  const doorLookup = {};
  doors.forEach(d => {
    doorLookup[d.id] = d.name || `Door ${d.id}`;
  });

  // Basic counts
  const totalEntries = entries.length;
  const successfulEntries = entries.filter(e => e.success).length;
  const failedEntries = entries.filter(e => !e.success).length;
  const successRate = totalEntries > 0 ? ((successfulEntries / totalEntries) * 100).toFixed(1) : 0;

  // Unique visitors
  const uniqueVisitorIds = new Set(entries.filter(e => e.user_id).map(e => e.user_id));
  const uniqueVisitors = uniqueVisitorIds.size;

  // Get unique dates
  const uniqueDates = new Set(entries.map(e => {
    const d = new Date(e.entryTime);
    return d.yyyymmdd();
  }));
  const avgEntriesPerDay = uniqueDates.size > 0 ? (totalEntries / uniqueDates.size).toFixed(1) : 0;

  // By hour analysis (5am - 11pm)
  const hourCounts = {};
  for (let h = 5; h <= 23; h++) {
    hourCounts[h] = { total: 0, successful: 0 };
  }

  entries.forEach(e => {
    const hour = new Date(e.entryTime).getHours();
    if (hour >= 5 && hour <= 23) {
      hourCounts[hour].total++;
      if (e.success) hourCounts[hour].successful++;
    }
  });

  const byHour = Object.entries(hourCounts).map(([hour, data]) => ({
    hour: parseInt(hour),
    label: `${hour.toString().padStart(2, '0')}:00`,
    total: data.total,
    successful: data.successful,
    successRate: data.total > 0 ? ((data.successful / data.total) * 100).toFixed(1) : 0
  }));

  // Find peak hour
  const peakHourData = byHour.reduce((max, h) => h.total > max.total ? h : max, { total: 0 });
  const peakHour = peakHourData.total > 0 ? peakHourData.label : null;

  // By day of week analysis
  const dayNames = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
  const dayCounts = {};
  dayNames.forEach((name, idx) => {
    dayCounts[idx] = { name, total: 0, successful: 0 };
  });

  entries.forEach(e => {
    const day = new Date(e.entryTime).getDay();
    dayCounts[day].total++;
    if (e.success) dayCounts[day].successful++;
  });

  const byDay = Object.entries(dayCounts).map(([dayIdx, data]) => ({
    day: data.name,
    dayIndex: parseInt(dayIdx),
    total: data.total,
    successful: data.successful,
    successRate: data.total > 0 ? ((data.successful / data.total) * 100).toFixed(1) : 0
  }));

  // Find peak day
  const peakDayData = byDay.reduce((max, d) => d.total > max.total ? d : max, { total: 0 });
  const peakDay = peakDayData.total > 0 ? peakDayData.day : null;

  // By door analysis
  const doorCounts = {};
  entries.forEach(e => {
    const doorId = e.door || 'unknown';
    const doorName = doorLookup[doorId] || `Door ${doorId}`;
    if (!doorCounts[doorId]) {
      doorCounts[doorId] = { id: doorId, name: doorName, total: 0, successful: 0 };
    }
    doorCounts[doorId].total++;
    if (e.success) doorCounts[doorId].successful++;
  });

  const byDoor = Object.values(doorCounts)
    .map(d => ({
      ...d,
      successRate: d.total > 0 ? ((d.successful / d.total) * 100).toFixed(1) : 0
    }))
    .sort((a, b) => b.total - a.total);

  // By card type analysis
  const cardCounts = {};
  entries.forEach(e => {
    const cardName = e.cardName || 'Unknown';
    if (!cardCounts[cardName]) {
      cardCounts[cardName] = { name: cardName, total: 0, successful: 0 };
    }
    cardCounts[cardName].total++;
    if (e.success) cardCounts[cardName].successful++;
  });

  const byCardType = Object.values(cardCounts)
    .map(c => ({
      ...c,
      successRate: c.total > 0 ? ((c.successful / c.total) * 100).toFixed(1) : 0
    }))
    .sort((a, b) => b.total - a.total);

  // Daily trend
  const dailyCounts = {};
  entries.forEach(e => {
    const date = new Date(e.entryTime).yyyymmdd();
    if (!dailyCounts[date]) {
      dailyCounts[date] = { date, total: 0, successful: 0, uniqueVisitors: new Set() };
    }
    dailyCounts[date].total++;
    if (e.success) dailyCounts[date].successful++;
    if (e.user_id) dailyCounts[date].uniqueVisitors.add(e.user_id);
  });

  const dailyTrend = Object.values(dailyCounts)
    .map(d => ({
      date: d.date,
      total: d.total,
      successful: d.successful,
      uniqueVisitors: d.uniqueVisitors.size,
      successRate: d.total > 0 ? ((d.successful / d.total) * 100).toFixed(1) : 0
    }))
    .sort((a, b) => a.date.localeCompare(b.date));

  // Top visitors
  const visitorCounts = {};
  entries.forEach(e => {
    if (e.user_id) {
      if (!visitorCounts[e.user_id]) {
        const memberName = e.Member
          ? `${e.Member.firstname || ''} ${e.Member.lastname || ''}`.trim()
          : `Member #${e.user_id}`;
        visitorCounts[e.user_id] = {
          id: e.user_id,
          name: memberName,
          entries: 0,
          lastVisit: null
        };
      }
      visitorCounts[e.user_id].entries++;
      const entryDate = new Date(e.entryTime);
      if (!visitorCounts[e.user_id].lastVisit || entryDate > new Date(visitorCounts[e.user_id].lastVisit)) {
        visitorCounts[e.user_id].lastVisit = entryDate.yyyymmdd();
      }
    }
  });

  const topVisitors = Object.values(visitorCounts)
    .sort((a, b) => b.entries - a.entries)
    .slice(0, 20);

  // Failed entry reasons
  const reasonCounts = {};
  entries.filter(e => !e.success && e.reason).forEach(e => {
    const reason = e.reason;
    if (!reasonCounts[reason]) {
      reasonCounts[reason] = { reason, count: 0 };
    }
    reasonCounts[reason].count++;
  });

  const failedReasons = Object.values(reasonCounts)
    .sort((a, b) => b.count - a.count);

  return {
    summary: {
      totalEntries,
      successfulEntries,
      failedEntries,
      successRate: parseFloat(successRate),
      uniqueVisitors,
      avgEntriesPerDay: parseFloat(avgEntriesPerDay),
      peakHour,
      peakDay
    },
    byHour,
    byDay,
    byDoor,
    byCardType,
    dailyTrend,
    topVisitors,
    failedReasons,
    rawEntries: entries.map(e => ({
      id: e.id,
      entryTime: e.entryTime,
      success: e.success,
      userId: e.user_id,
      memberName: e.Member ? `${e.Member.firstname || ''} ${e.Member.lastname || ''}`.trim() : null,
      cardName: e.cardName,
      door: e.door,
      doorName: doorLookup[e.door] || `Door ${e.door}`,
      reason: e.reason
    }))
  };
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
  try {
    const { clubId } = req.params;
    const { fromDate, toDate } = req.query;

    if (!fromDate || !toDate) {
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

    const domain = club.Zoezi_Domain;
    const apiKey = club.Zoezi_Api_Key;

    // Fetch entries
    const entries = await zoeziFetch(domain, apiKey, `/api/entry/get?fromDate=${fromDate}&toDate=${toDate}`);

    // Fetch doors/resources for door names
    let doors = [];
    try {
      const resources = await zoeziFetch(domain, apiKey, '/api/resource/get/all');
      doors = resources || [];
    } catch (e) {
      console.log('Could not fetch resources:', e.message);
    }

    // Process analytics
    const analytics = processEntryAnalytics(entries, doors);

    res.json({
      ...analytics,
      club: {
        id: club.Club_Zoezi_ID,
        name: club.Club_name,
        domain: club.Zoezi_Domain
      },
      dateRange: { fromDate, toDate }
    });
  } catch (error) {
    console.error('Error fetching analytics:', error);
    res.status(500).json({ error: 'Failed to fetch analytics', message: error.message });
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
  try {
    const { token, fromDate, toDate } = req.query;

    if (!token) {
      return res.status(401).json({ error: 'Token required' });
    }

    const verification = verifyEmbedToken(token);
    if (!verification.valid) {
      return res.status(401).json({ error: verification.error });
    }

    if (!fromDate || !toDate) {
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

    const domain = club.Zoezi_Domain;
    const apiKey = club.Zoezi_Api_Key;

    // Fetch entries
    const entries = await zoeziFetch(domain, apiKey, `/api/entry/get?fromDate=${fromDate}&toDate=${toDate}`);

    // Fetch doors
    let doors = [];
    try {
      const resources = await zoeziFetch(domain, apiKey, '/api/resource/get/all');
      doors = resources || [];
    } catch (e) {
      console.log('Could not fetch resources:', e.message);
    }

    // Process analytics
    const analytics = processEntryAnalytics(entries, doors);

    res.json({
      ...analytics,
      club: {
        id: club.Club_Zoezi_ID,
        name: club.Club_name,
        domain: club.Zoezi_Domain
      },
      dateRange: { fromDate, toDate }
    });
  } catch (error) {
    console.error('Embed analytics error:', error);
    res.status(500).json({ error: 'Failed to fetch analytics', message: error.message });
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

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   StrongSales Entry Analytics Dashboard                       ║
║   ─────────────────────────────────────                       ║
║   Server running on port ${PORT}                                 ║
║   http://localhost:${PORT}                                       ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
  `);
});
