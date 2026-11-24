-- GhostMetrics ClickHouse Schema (MergeTree + Daily Rollup MaterializedView)
-- Privacy-first: zero cookies, zero raw IP addresses, daily rotating RAM-salted visitor_hash.

CREATE TABLE IF NOT EXISTS ghostmetrics_events
(
    ts             DateTime('UTC'),
    site_id        LowCardinality(String),
    visitor_hash   FixedString(16),
    event_name     LowCardinality(String),
    path           String,
    referrer_host  LowCardinality(String),
    utm_source     LowCardinality(String),
    country        LowCardinality(FixedString(2)),
    browser        LowCardinality(String),
    os             LowCardinality(String),
    device         LowCardinality(String)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(ts)
ORDER BY (site_id, toDate(ts), visitor_hash, ts)
TTL ts + INTERVAL 365 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS ghostmetrics_daily_stats
(
    day            Date,
    site_id        LowCardinality(String),
    path           String,
    referrer_host  LowCardinality(String),
    visitors       AggregateFunction(uniqExact, FixedString(16)),
    pageviews      SimpleAggregateFunction(sum, UInt64),
    custom_events  SimpleAggregateFunction(sum, UInt64)
)
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (site_id, day, path, referrer_host);

CREATE MATERIALIZED VIEW IF NOT EXISTS ghostmetrics_daily_stats_mv
TO ghostmetrics_daily_stats
AS
SELECT
    toDate(ts) AS day,
    site_id,
    path,
    referrer_host,
    uniqExactState(visitor_hash) AS visitors,
    countIf(event_name = 'pageview') AS pageviews,
    countIf(event_name != 'pageview') AS custom_events
FROM ghostmetrics_events
GROUP BY day, site_id, path, referrer_host;

-- Example analytical queries:
--
-- 1. 7-day unique visitors and pageviews per day:
-- SELECT
--     day,
--     uniqExactMerge(visitors) AS unique_visitors,
--     sum(pageviews) AS total_pageviews
-- FROM ghostmetrics_daily_stats
-- WHERE site_id = 'demo.ghostmetrics.local'
--   AND day >= today() - 7
-- GROUP BY day
-- ORDER BY day ASC;
--
-- 2. Top 10 pages by unique visitors:
-- SELECT
--     path,
--     uniqExact(visitor_hash) AS visitors,
--     countIf(event_name = 'pageview') AS pageviews
-- FROM ghostmetrics_events
-- WHERE site_id = 'demo.ghostmetrics.local'
--   AND ts >= now() - INTERVAL 7 DAY
-- GROUP BY path
-- ORDER BY visitors DESC
-- LIMIT 10;
