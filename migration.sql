-- StrongSales Entry Analytics Dashboard - Database Migration
-- Moves from in-memory Zoezi API fetching to Supabase-backed storage + SQL analytics

-- ============================================================
-- TABLES
-- ============================================================

-- Entry events synced from Zoezi
CREATE TABLE IF NOT EXISTS entry_events (
  club_id text NOT NULL,
  zoezi_entry_id bigint NOT NULL,
  entry_time timestamptz NOT NULL,
  entry_date date NOT NULL,           -- local date (Europe/Stockholm)
  entry_hour smallint NOT NULL,       -- local hour 0-23
  entry_dow smallint NOT NULL,        -- local day of week 0=Sunday..6=Saturday
  success boolean NOT NULL DEFAULT true,
  user_id bigint,
  member_id bigint,
  door_id text,
  reason text,
  card_name text,
  site_ids bigint[] NOT NULL DEFAULT '{}',
  PRIMARY KEY (club_id, zoezi_entry_id)
);

-- Sync tracking per club per day
CREATE TABLE IF NOT EXISTS entry_sync_days (
  club_id text NOT NULL,
  sync_date date NOT NULL,
  is_final boolean NOT NULL DEFAULT false,
  entry_count integer DEFAULT 0,
  last_synced_at timestamptz DEFAULT now(),
  PRIMARY KEY (club_id, sync_date)
);

-- Door names cache
CREATE TABLE IF NOT EXISTS club_doors (
  club_id text NOT NULL,
  door_id text NOT NULL,
  door_name text NOT NULL,
  updated_at timestamptz DEFAULT now(),
  PRIMARY KEY (club_id, door_id)
);

-- Site names cache
CREATE TABLE IF NOT EXISTS club_sites (
  club_id text NOT NULL,
  site_id bigint NOT NULL,
  site_name text NOT NULL,
  updated_at timestamptz DEFAULT now(),
  PRIMARY KEY (club_id, site_id)
);

-- ============================================================
-- INDEXES
-- ============================================================

CREATE INDEX IF NOT EXISTS idx_entry_events_club_date ON entry_events (club_id, entry_date, entry_time DESC);
CREATE INDEX IF NOT EXISTS idx_entry_events_club_door ON entry_events (club_id, door_id, entry_date);
CREATE INDEX IF NOT EXISTS idx_entry_events_club_card ON entry_events (club_id, card_name, entry_date);
CREATE INDEX IF NOT EXISTS idx_entry_events_sites_gin ON entry_events USING gin (site_ids);

-- ============================================================
-- FUNCTION: get_entry_analytics
-- ============================================================

CREATE OR REPLACE FUNCTION get_entry_analytics(
  p_club_id text,
  p_from_date date,
  p_to_date date,
  p_doors text[] DEFAULT NULL,
  p_cards text[] DEFAULT NULL,
  p_sites bigint[] DEFAULT NULL,
  p_status text DEFAULT 'all',
  p_unique_visits boolean DEFAULT false
) RETURNS jsonb
LANGUAGE plpgsql
SET statement_timeout = '120s'
AS $$
DECLARE
  v_result jsonb;
  v_summary jsonb;
  v_by_hour jsonb;
  v_by_day jsonb;
  v_by_door jsonb;
  v_by_card jsonb;
  v_daily_trend jsonb;
  v_top_visitors jsonb;
  v_failed_reasons jsonb;
  v_total bigint;
  v_successful bigint;
  v_failed bigint;
  v_unique_visitors bigint;
  v_num_days bigint;
  v_peak_hour text;
  v_peak_day text;
BEGIN
  -- Create narrow temp table (only columns needed for aggregations)
  CREATE TEMP TABLE _filtered ON COMMIT DROP AS
  SELECT
    COALESCE(e.user_id, e.member_id) AS visitor_id,
    e.entry_date,
    e.entry_hour,
    e.entry_dow,
    e.entry_time,
    e.success,
    e.door_id,
    e.card_name,
    e.reason,
    e.site_ids,
    e.club_id
  FROM entry_events e
  WHERE e.club_id = p_club_id
    AND e.entry_date BETWEEN p_from_date AND p_to_date
    AND (p_doors IS NULL OR e.door_id = ANY(p_doors))
    AND (p_cards IS NULL OR e.card_name = ANY(p_cards))
    AND (p_sites IS NULL OR e.site_ids && p_sites)
    AND (
      p_status = 'all'
      OR (p_status = 'success' AND e.success = true)
      OR (p_status = 'failed' AND e.success = false)
    );

  -- Give the planner stats on the temp table
  ANALYZE _filtered;

  -- If unique visits, deduplicate: keep one entry per visitor per day
  IF p_unique_visits THEN
    CREATE TEMP TABLE _deduped ON COMMIT DROP AS
    (
      -- Entries without any visitor ID: keep all
      SELECT * FROM _filtered WHERE visitor_id IS NULL
    )
    UNION ALL
    (
      -- Entries with visitor ID: keep earliest per visitor per day
      SELECT DISTINCT ON (visitor_id, entry_date) *
      FROM _filtered
      WHERE visitor_id IS NOT NULL
      ORDER BY visitor_id, entry_date, entry_time ASC
    );

    DROP TABLE _filtered;
    ALTER TABLE _deduped RENAME TO _filtered;
    ANALYZE _filtered;
  END IF;

  -- Summary counts (use visitor_id as visitor_id throughout)
  SELECT count(*), coalesce(sum(CASE WHEN success THEN 1 ELSE 0 END), 0),
         coalesce(sum(CASE WHEN NOT success THEN 1 ELSE 0 END), 0),
         count(DISTINCT visitor_id),
         count(DISTINCT entry_date)
  INTO v_total, v_successful, v_failed, v_unique_visitors, v_num_days
  FROM _filtered;

  -- Peak hour
  SELECT lpad(entry_hour::text, 2, '0') || ':00'
  INTO v_peak_hour
  FROM _filtered
  GROUP BY entry_hour
  ORDER BY count(*) DESC
  LIMIT 1;

  -- Peak day
  SELECT CASE entry_dow
    WHEN 0 THEN 'Sunday' WHEN 1 THEN 'Monday' WHEN 2 THEN 'Tuesday'
    WHEN 3 THEN 'Wednesday' WHEN 4 THEN 'Thursday' WHEN 5 THEN 'Friday'
    WHEN 6 THEN 'Saturday'
  END
  INTO v_peak_day
  FROM _filtered
  GROUP BY entry_dow
  ORDER BY count(*) DESC
  LIMIT 1;

  -- Build summary
  v_summary := jsonb_build_object(
    'totalEntries', v_total,
    'successfulEntries', v_successful,
    'failedEntries', v_failed,
    'successRate', CASE WHEN v_total > 0 THEN round((v_successful::numeric / v_total * 100), 1) ELSE 0 END,
    'uniqueVisitors', v_unique_visitors,
    'avgEntriesPerDay', CASE WHEN v_num_days > 0 THEN round((v_total::numeric / v_num_days), 1) ELSE 0 END,
    'peakHour', v_peak_hour,
    'peakDay', v_peak_day
  );

  -- By hour (all 24)
  SELECT coalesce(jsonb_agg(row_data ORDER BY hour), '[]'::jsonb)
  INTO v_by_hour
  FROM (
    SELECT h.hour,
           jsonb_build_object(
             'hour', h.hour,
             'label', lpad(h.hour::text, 2, '0') || ':00',
             'total', coalesce(c.total, 0),
             'successful', coalesce(c.successful, 0),
             'successRate', CASE WHEN coalesce(c.total, 0) > 0
               THEN round((coalesce(c.successful, 0)::numeric / c.total * 100), 1)::text
               ELSE '0' END
           ) AS row_data
    FROM generate_series(0, 23) AS h(hour)
    LEFT JOIN (
      SELECT entry_hour,
             count(*) AS total,
             sum(CASE WHEN success THEN 1 ELSE 0 END) AS successful
      FROM _filtered
      GROUP BY entry_hour
    ) c ON c.entry_hour = h.hour
  ) sub;

  -- By day of week (all 7, Sunday=0)
  SELECT coalesce(jsonb_agg(row_data ORDER BY day_idx), '[]'::jsonb)
  INTO v_by_day
  FROM (
    SELECT d.day_idx,
           jsonb_build_object(
             'day', CASE d.day_idx
               WHEN 0 THEN 'Sunday' WHEN 1 THEN 'Monday' WHEN 2 THEN 'Tuesday'
               WHEN 3 THEN 'Wednesday' WHEN 4 THEN 'Thursday' WHEN 5 THEN 'Friday'
               WHEN 6 THEN 'Saturday'
             END,
             'dayIndex', d.day_idx,
             'total', coalesce(c.total, 0),
             'successful', coalesce(c.successful, 0),
             'successRate', CASE WHEN coalesce(c.total, 0) > 0
               THEN round((coalesce(c.successful, 0)::numeric / c.total * 100), 1)::text
               ELSE '0' END
           ) AS row_data
    FROM generate_series(0, 6) AS d(day_idx)
    LEFT JOIN (
      SELECT entry_dow,
             count(*) AS total,
             sum(CASE WHEN success THEN 1 ELSE 0 END) AS successful
      FROM _filtered
      GROUP BY entry_dow
    ) c ON c.entry_dow = d.day_idx
  ) sub;

  -- By door (sorted by total desc)
  SELECT coalesce(jsonb_agg(row_data ORDER BY total DESC), '[]'::jsonb)
  INTO v_by_door
  FROM (
    SELECT jsonb_build_object(
             'id', f.door_id,
             'name', coalesce(cd.door_name, 'Door ' || coalesce(f.door_id, 'unknown')),
             'total', count(*),
             'successful', sum(CASE WHEN f.success THEN 1 ELSE 0 END),
             'successRate', CASE WHEN count(*) > 0
               THEN round((sum(CASE WHEN f.success THEN 1 ELSE 0 END)::numeric / count(*) * 100), 1)::text
               ELSE '0' END
           ) AS row_data,
           count(*) AS total
    FROM _filtered f
    LEFT JOIN club_doors cd ON cd.club_id = f.club_id AND cd.door_id = f.door_id
    GROUP BY f.door_id, cd.door_name
  ) sub;

  -- By card type (sorted by total desc)
  SELECT coalesce(jsonb_agg(row_data ORDER BY total DESC), '[]'::jsonb)
  INTO v_by_card
  FROM (
    SELECT jsonb_build_object(
             'name', coalesce(card_name, 'Unknown'),
             'total', count(*),
             'successful', sum(CASE WHEN success THEN 1 ELSE 0 END),
             'successRate', CASE WHEN count(*) > 0
               THEN round((sum(CASE WHEN success THEN 1 ELSE 0 END)::numeric / count(*) * 100), 1)::text
               ELSE '0' END
           ) AS row_data,
           count(*) AS total
    FROM _filtered
    GROUP BY card_name
  ) sub;

  -- Daily trend (sorted by date)
  SELECT coalesce(jsonb_agg(row_data ORDER BY dt), '[]'::jsonb)
  INTO v_daily_trend
  FROM (
    SELECT entry_date AS dt,
           jsonb_build_object(
             'date', entry_date::text,
             'total', count(*),
             'successful', sum(CASE WHEN success THEN 1 ELSE 0 END),
             'uniqueVisitors', count(DISTINCT visitor_id),
             'successRate', CASE WHEN count(*) > 0
               THEN round((sum(CASE WHEN success THEN 1 ELSE 0 END)::numeric / count(*) * 100), 1)::text
               ELSE '0' END
           ) AS row_data
    FROM _filtered
    GROUP BY entry_date
  ) sub;

  -- Top visitors (top 20)
  SELECT coalesce(jsonb_agg(row_data ORDER BY entries DESC), '[]'::jsonb)
  INTO v_top_visitors
  FROM (
    SELECT jsonb_build_object(
             'id', visitor_id,
             'name', 'Member #' || visitor_id,
             'entries', count(*),
             'lastVisit', max(entry_date)::text
           ) AS row_data,
           count(*) AS entries
    FROM _filtered
    WHERE visitor_id IS NOT NULL
    GROUP BY visitor_id
    ORDER BY count(*) DESC
    LIMIT 20
  ) sub;

  -- Failed reasons (sorted by count desc)
  SELECT coalesce(jsonb_agg(row_data ORDER BY cnt DESC), '[]'::jsonb)
  INTO v_failed_reasons
  FROM (
    SELECT jsonb_build_object(
             'reason', reason,
             'count', count(*)
           ) AS row_data,
           count(*) AS cnt
    FROM _filtered
    WHERE NOT success AND reason IS NOT NULL AND reason <> ''
    GROUP BY reason
  ) sub;

  -- Combine
  v_result := jsonb_build_object(
    'summary', v_summary,
    'byHour', v_by_hour,
    'byDay', v_by_day,
    'byDoor', v_by_door,
    'byCardType', v_by_card,
    'dailyTrend', v_daily_trend,
    'topVisitors', v_top_visitors,
    'failedReasons', v_failed_reasons,
    'bySite', (
      SELECT coalesce(jsonb_agg(jsonb_build_object(
        'id', s.site_id,
        'name', coalesce(cs.site_name, 'Site ' || s.site_id),
        'count', s.cnt
      ) ORDER BY s.cnt DESC), '[]'::jsonb)
      FROM (
        SELECT unnest(site_ids) AS site_id, count(*) AS cnt
        FROM _filtered
        WHERE array_length(site_ids, 1) > 0
        GROUP BY 1
      ) s
      LEFT JOIN club_sites cs ON cs.club_id = p_club_id AND cs.site_id = s.site_id
    )
  );

  RETURN v_result;
END;
$$;

-- ============================================================
-- FUNCTION: get_entry_page
-- ============================================================

CREATE OR REPLACE FUNCTION get_entry_page(
  p_club_id text,
  p_from_date date,
  p_to_date date,
  p_doors text[] DEFAULT NULL,
  p_cards text[] DEFAULT NULL,
  p_sites bigint[] DEFAULT NULL,
  p_status text DEFAULT 'all',
  p_page int DEFAULT 1,
  p_limit int DEFAULT 20
) RETURNS jsonb
LANGUAGE plpgsql
SET statement_timeout = '120s'
AS $$
DECLARE
  v_total bigint;
  v_total_pages int;
  v_offset int;
  v_entries jsonb;
BEGIN
  v_offset := (p_page - 1) * p_limit;

  -- Count total
  SELECT count(*)
  INTO v_total
  FROM entry_events e
  WHERE e.club_id = p_club_id
    AND e.entry_date BETWEEN p_from_date AND p_to_date
    AND (p_doors IS NULL OR e.door_id = ANY(p_doors))
    AND (p_cards IS NULL OR e.card_name = ANY(p_cards))
    AND (p_sites IS NULL OR e.site_ids && p_sites)
    AND (
      p_status = 'all'
      OR (p_status = 'success' AND e.success = true)
      OR (p_status = 'failed' AND e.success = false)
    );

  v_total_pages := GREATEST(1, ceil(v_total::numeric / p_limit));

  -- Get page of entries
  SELECT coalesce(jsonb_agg(row_data), '[]'::jsonb)
  INTO v_entries
  FROM (
    SELECT jsonb_build_object(
             'entryTime', e.entry_time,
             'success', e.success,
             'userId', COALESCE(e.user_id, e.member_id),
             'memberName', NULL,
             'cardName', coalesce(e.card_name, 'Unknown'),
             'door', e.door_id,
             'doorName', coalesce(cd.door_name, 'Door ' || coalesce(e.door_id, 'unknown')),
             'reason', e.reason,
             'sites', e.site_ids
           ) AS row_data
    FROM entry_events e
    LEFT JOIN club_doors cd ON cd.club_id = e.club_id AND cd.door_id = e.door_id
    WHERE e.club_id = p_club_id
      AND e.entry_date BETWEEN p_from_date AND p_to_date
      AND (p_doors IS NULL OR e.door_id = ANY(p_doors))
      AND (p_cards IS NULL OR e.card_name = ANY(p_cards))
      AND (p_sites IS NULL OR e.site_ids && p_sites)
      AND (
        p_status = 'all'
        OR (p_status = 'success' AND e.success = true)
        OR (p_status = 'failed' AND e.success = false)
      )
    ORDER BY e.entry_time DESC
    LIMIT p_limit
    OFFSET v_offset
  ) sub;

  RETURN jsonb_build_object(
    'entries', v_entries,
    'total', v_total,
    'page', p_page,
    'totalPages', v_total_pages
  );
END;
$$;
