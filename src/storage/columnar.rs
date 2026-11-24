use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::Instant;

use chrono::{DateTime, Duration, TimeZone, Utc};
use serde::{Deserialize, Serialize};

use crate::plugins::{FunnelDefinition, PluginEngine, PluginMetrics, SpikeAlert};
use crate::TRACKER_JS;

/// Canonical privacy-safe event record written to UTC-day `.chcol` partitions
/// and ClickHouse `JSONEachRow` batches. Contains ZERO raw IPs and ZERO cookies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRecord {
    pub ts: i64,
    pub site_id: String,
    pub visitor_hash: String,
    pub event_name: String,
    pub path: String,
    pub referrer_host: String,
    pub utm_source: String,
    pub country: String,
    pub browser: String,
    pub os: String,
    pub device: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeriesPoint {
    pub bucket: String,
    pub label: String,
    pub visitors: u64,
    pub pageviews: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageStat {
    pub path: String,
    pub visitors: u64,
    pub views: u64,
    pub bounce_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DimensionStat {
    pub name: String,
    pub visitors: u64,
    pub share: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomEventStat {
    pub name: String,
    pub count: u64,
    pub visitors: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunnelStepResult {
    pub label: String,
    pub matcher: String,
    pub visitors: u64,
    pub conversion_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunnelResult {
    pub plugin_id: String,
    pub name: String,
    pub overall_conversion: f64,
    pub steps: Vec<FunnelStepResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceStatus {
    pub cookies_set: u64,
    pub raw_ips_stored: u64,
    pub tracker_bytes: usize,
    pub salt_rotation: String,
    pub respect_dnt: bool,
    pub clickhouse_enabled: bool,
    pub partition_count: usize,
    pub total_rows: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct ComplianceContext {
    pub respect_dnt: bool,
    pub clickhouse_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsResponse {
    pub site: String,
    pub range: String,
    pub query_ms: f64,
    pub unique_visitors: u64,
    pub pageviews: u64,
    pub custom_events_total: u64,
    pub views_per_visit: f64,
    pub bounce_rate: f64,
    pub avg_session_duration_sec: f64,
    pub active_visitors: u64,
    pub series: Vec<SeriesPoint>,
    pub top_pages: Vec<PageStat>,
    pub top_referrers: Vec<DimensionStat>,
    pub utm_sources: Vec<DimensionStat>,
    pub browsers: Vec<DimensionStat>,
    pub os: Vec<DimensionStat>,
    pub devices: Vec<DimensionStat>,
    pub countries: Vec<DimensionStat>,
    pub custom_events: Vec<CustomEventStat>,
    pub funnels: Vec<FunnelResult>,
    pub spike_alert: Option<SpikeAlert>,
    pub plugin_metrics: PluginMetrics,
    pub compliance: ComplianceStatus,
}

/// Low-cardinality string dictionary mapping strings to compact `u32` IDs.
#[derive(Default)]
struct StringDict {
    to_id: HashMap<String, u32>,
    values: Vec<String>,
}

impl StringDict {
    fn intern(&mut self, s: &str) -> u32 {
        if let Some(&id) = self.to_id.get(s) {
            return id;
        }
        let id = self.values.len() as u32;
        self.values.push(s.to_string());
        self.to_id.insert(s.to_string(), id);
        id
    }

    fn get_id(&self, s: &str) -> Option<u32> {
        self.to_id.get(s).copied()
    }

    fn resolve(&self, id: u32) -> &str {
        self.values
            .get(id as usize)
            .map(String::as_str)
            .unwrap_or("")
    }
}

/// In-memory columnar vectors modeled after ClickHouse MergeTree columns.
#[derive(Default)]
struct ColumnarTable {
    ts: Vec<i64>,
    visitor_hash: Vec<u64>,
    site_id: Vec<u32>,
    event_name: Vec<u32>,
    path: Vec<u32>,
    referrer_host: Vec<u32>,
    utm_source: Vec<u32>,
    country: Vec<u32>,
    browser: Vec<u32>,
    os: Vec<u32>,
    device: Vec<u32>,

    site_dict: StringDict,
    event_dict: StringDict,
    path_dict: StringDict,
    ref_dict: StringDict,
    utm_dict: StringDict,
    country_dict: StringDict,
    browser_dict: StringDict,
    os_dict: StringDict,
    device_dict: StringDict,

    registered_sites: BTreeSet<String>,
    partitions: BTreeSet<String>,
}

impl ColumnarTable {
    fn len(&self) -> usize {
        self.ts.len()
    }

    fn push(&mut self, ev: &EventRecord, partition_day: String) {
        let vh = u64::from_str_radix(&ev.visitor_hash, 16).unwrap_or_else(|_| {
            // Stable fallback FNV-1a 64-bit if external hash is non-hex
            let mut h: u64 = 0xcbf29ce484222325;
            for b in ev.visitor_hash.as_bytes() {
                h ^= u64::from(*b);
                h = h.wrapping_mul(0x100000001b3);
            }
            h
        });

        let sid = self.site_dict.intern(&ev.site_id);
        let eid = self.event_dict.intern(&ev.event_name);
        let pid = self.path_dict.intern(&ev.path);
        let rid = self.ref_dict.intern(&ev.referrer_host);
        let uid = self.utm_dict.intern(&ev.utm_source);
        let cid = self.country_dict.intern(&ev.country);
        let bid = self.browser_dict.intern(&ev.browser);
        let oid = self.os_dict.intern(&ev.os);
        let did = self.device_dict.intern(&ev.device);

        self.ts.push(ev.ts);
        self.visitor_hash.push(vh);
        self.site_id.push(sid);
        self.event_name.push(eid);
        self.path.push(pid);
        self.referrer_host.push(rid);
        self.utm_source.push(uid);
        self.country.push(cid);
        self.browser.push(bid);
        self.os.push(oid);
        self.device.push(did);

        self.registered_sites.insert(ev.site_id.clone());
        self.partitions.insert(partition_day);
    }

    fn row_to_record(&self, idx: usize) -> EventRecord {
        EventRecord {
            ts: self.ts[idx],
            site_id: self.site_dict.resolve(self.site_id[idx]).to_string(),
            visitor_hash: format!("{:016x}", self.visitor_hash[idx]),
            event_name: self.event_dict.resolve(self.event_name[idx]).to_string(),
            path: self.path_dict.resolve(self.path[idx]).to_string(),
            referrer_host: self.ref_dict.resolve(self.referrer_host[idx]).to_string(),
            utm_source: self.utm_dict.resolve(self.utm_source[idx]).to_string(),
            country: self.country_dict.resolve(self.country[idx]).to_string(),
            browser: self.browser_dict.resolve(self.browser[idx]).to_string(),
            os: self.os_dict.resolve(self.os[idx]).to_string(),
            device: self.device_dict.resolve(self.device[idx]).to_string(),
        }
    }
}

/// Embedded ClickHouse-style partitioned columnar storage engine.
pub struct ColumnarStore {
    data_dir: PathBuf,
    partitions_dir: PathBuf,
    sites_file: PathBuf,
    table: RwLock<ColumnarTable>,
}

impl ColumnarStore {
    pub fn open(data_dir: impl AsRef<Path>) -> io::Result<Self> {
        let data_dir = data_dir.as_ref().to_path_buf();
        let partitions_dir = data_dir.join("partitions");
        let sites_file = data_dir.join("sites.json");
        fs::create_dir_all(&partitions_dir)?;

        let mut table = ColumnarTable::default();

        // Load registered sites if present
        if sites_file.exists() {
            if let Ok(raw) = fs::read_to_string(&sites_file) {
                if let Ok(sites) = serde_json::from_str::<Vec<String>>(&raw) {
                    for s in sites {
                        table.registered_sites.insert(s);
                    }
                }
            }
        }

        // Load all UTC-day `.chcol` partitions sorted chronologically
        let mut partition_files: Vec<PathBuf> = fs::read_dir(&partitions_dir)?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("chcol"))
            .collect();
        partition_files.sort();

        for path in partition_files {
            let day_stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string();
            let file = File::open(&path)?;
            let reader = BufReader::new(file);
            for line in reader.lines() {
                let line = line?;
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                if let Ok(record) = serde_json::from_str::<EventRecord>(trimmed) {
                    table.push(&record, day_stem.clone());
                }
            }
        }

        Ok(Self {
            data_dir,
            partitions_dir,
            sites_file,
            table: RwLock::new(table),
        })
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn total_rows(&self) -> usize {
        self.table.read().expect("columnar read lock").len()
    }

    pub fn partition_count(&self) -> usize {
        self.table
            .read()
            .expect("columnar read lock")
            .partitions
            .len()
    }

    pub fn list_sites(&self) -> Vec<String> {
        let guard = self.table.read().expect("columnar read lock");
        guard.registered_sites.iter().cloned().collect()
    }

    pub fn register_site(&self, site: &str) -> io::Result<()> {
        let sites_snapshot = {
            let mut guard = self.table.write().expect("columnar write lock");
            guard.registered_sites.insert(site.to_string());
            guard.registered_sites.iter().cloned().collect::<Vec<_>>()
        };
        let payload = serde_json::to_string_pretty(&sites_snapshot)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(&self.sites_file, payload)
    }

    /// Appends a single privacy-safe event durably to its UTC-day `.chcol` partition
    /// and updates the in-RAM dictionary-encoded columnar vectors.
    pub fn append(&self, event: EventRecord) -> io::Result<()> {
        let day = partition_day_from_ts(event.ts);
        let partition_path = self.partitions_dir.join(format!("{day}.chcol"));
        let line = serde_json::to_string(&event)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let mut guard = self.table.write().expect("columnar write lock");
        let is_new_file = !partition_path.exists();
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&partition_path)?;
        if is_new_file {
            writeln!(file, "# GHOSTMETRICS_CHCOL_V1 partition={day}")?;
        }
        writeln!(file, "{line}")?;
        guard.push(&event, day);
        Ok(())
    }

    /// Batch-appends events grouped by UTC-day partition for fast seeding or bulk import.
    pub fn append_batch(&self, events: &[EventRecord]) -> io::Result<usize> {
        if events.is_empty() {
            return Ok(0);
        }
        let mut by_day: HashMap<String, Vec<&EventRecord>> = HashMap::new();
        for ev in events {
            by_day
                .entry(partition_day_from_ts(ev.ts))
                .or_default()
                .push(ev);
        }

        let mut guard = self.table.write().expect("columnar write lock");
        for (day, batch) in by_day {
            let partition_path = self.partitions_dir.join(format!("{day}.chcol"));
            let is_new = !partition_path.exists();
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&partition_path)?;
            if is_new {
                writeln!(file, "# GHOSTMETRICS_CHCOL_V1 partition={day}")?;
            }
            let mut buf = String::with_capacity(batch.len() * 196);
            for ev in &batch {
                let line = serde_json::to_string(ev)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                buf.push_str(&line);
                buf.push('\n');
                guard.push(ev, day.clone());
            }
            file.write_all(buf.as_bytes())?;
        }

        // Persist sites registry
        let sites_snapshot: Vec<String> = guard.registered_sites.iter().cloned().collect();
        drop(guard);
        let payload = serde_json::to_string_pretty(&sites_snapshot)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(&self.sites_file, payload)?;

        Ok(events.len())
    }

    /// Exports stored events filtered optionally by site and lookback days.
    pub fn export_events(&self, site: Option<&str>, range_days: Option<i64>) -> Vec<EventRecord> {
        let guard = self.table.read().expect("columnar read lock");
        let target_site = site.and_then(|s| guard.site_dict.get_id(s));
        if site.is_some() && target_site.is_none() {
            return Vec::new();
        }
        let cutoff = range_days.map(|d| Utc::now().timestamp() - d * 86_400);

        let mut out = Vec::new();
        for i in 0..guard.len() {
            if let Some(sid) = target_site {
                if guard.site_id[i] != sid {
                    continue;
                }
            }
            if let Some(c) = cutoff {
                if guard.ts[i] < c {
                    continue;
                }
            }
            out.push(guard.row_to_record(i));
        }
        out.sort_by_key(|r| r.ts);
        out
    }

    /// Executes a sub-millisecond in-RAM columnar OLAP scan for `site` over `range` (`24h`, `7d`, `30d`, `90d`).
    pub fn query_stats(
        &self,
        site: &str,
        range: &str,
        plugins: &PluginEngine,
        compliance_ctx: ComplianceContext,
    ) -> StatsResponse {
        let start = Instant::now();
        let now = Utc::now();
        let now_ts = now.timestamp();
        let (canonical_range, hourly, num_buckets, window_secs) = parse_range(range);
        let cutoff_ts = now_ts - window_secs;
        let active_cutoff_ts = now_ts - 300;

        let guard = self.table.read().expect("columnar read lock");
        let target_site_id = guard.site_dict.get_id(site);
        let pageview_event_id = guard.event_dict.get_id("pageview");

        // Build empty continuous time-series buckets
        let mut bucket_keys: Vec<(String, String)> = Vec::with_capacity(num_buckets);
        let mut bucket_index: HashMap<String, usize> = HashMap::with_capacity(num_buckets);
        if hourly {
            for h in (0..num_buckets).rev() {
                let dt = now - Duration::hours(h as i64);
                let key = dt.format("%Y-%m-%d %H:00").to_string();
                let label = dt.format("%H:00").to_string();
                bucket_index.insert(key.clone(), bucket_keys.len());
                bucket_keys.push((key, label));
            }
        } else {
            for d in (0..num_buckets).rev() {
                let dt = now - Duration::days(d as i64);
                let key = dt.format("%Y-%m-%d").to_string();
                let label = dt.format("%b %d").to_string();
                bucket_index.insert(key.clone(), bucket_keys.len());
                bucket_keys.push((key, label));
            }
        }

        let mut bucket_visitors: Vec<HashSet<u64>> = vec![HashSet::new(); num_buckets];
        let mut bucket_pageviews: Vec<u64> = vec![0; num_buckets];

        let mut all_visitors: HashSet<u64> = HashSet::new();
        let mut active_set: HashSet<u64> = HashSet::new();
        let mut total_pageviews: u64 = 0;
        let mut custom_events_total: u64 = 0;

        // Per-visitor state for bounce rate & session duration: (pv_count, min_ts, max_ts, first_path_id)
        let mut visitor_sessions: HashMap<u64, (u64, i64, i64, Option<u32>)> = HashMap::new();

        // Dimension aggregations keyed by dictionary u32 ID
        let mut page_views: HashMap<u32, u64> = HashMap::new();
        let mut page_visitors: HashMap<u32, HashSet<u64>> = HashMap::new();
        let mut ref_visitors: HashMap<u32, HashSet<u64>> = HashMap::new();
        let mut utm_visitors: HashMap<u32, HashSet<u64>> = HashMap::new();
        let mut browser_visitors: HashMap<u32, HashSet<u64>> = HashMap::new();
        let mut os_visitors: HashMap<u32, HashSet<u64>> = HashMap::new();
        let mut device_visitors: HashMap<u32, HashSet<u64>> = HashMap::new();
        let mut country_visitors: HashMap<u32, HashSet<u64>> = HashMap::new();
        let mut custom_event_counts: HashMap<u32, (u64, HashSet<u64>)> = HashMap::new();

        // Matched row indices for sequential funnel evaluation
        let mut matched_indices: Vec<usize> = Vec::new();

        if let Some(sid) = target_site_id {
            let n = guard.len();
            for i in 0..n {
                if guard.site_id[i] != sid {
                    continue;
                }
                let ts = guard.ts[i];
                let vh = guard.visitor_hash[i];

                if ts >= active_cutoff_ts {
                    active_set.insert(vh);
                }
                if ts < cutoff_ts {
                    continue;
                }

                matched_indices.push(i);
                all_visitors.insert(vh);

                let is_pv = pageview_event_id.map(|id| guard.event_name[i] == id).unwrap_or(false);
                let path_id = guard.path[i];

                let entry = visitor_sessions
                    .entry(vh)
                    .or_insert((0, ts, ts, None));
                if ts < entry.1 {
                    entry.1 = ts;
                }
                if ts > entry.2 {
                    entry.2 = ts;
                }
                if is_pv {
                    total_pageviews += 1;
                    entry.0 += 1;
                    if entry.3.is_none() {
                        entry.3 = Some(path_id);
                    }
                    *page_views.entry(path_id).or_insert(0) += 1;
                    page_visitors.entry(path_id).or_default().insert(vh);
                } else {
                    custom_events_total += 1;
                    let ev_entry = custom_event_counts
                        .entry(guard.event_name[i])
                        .or_insert_with(|| (0, HashSet::new()));
                    ev_entry.0 += 1;
                    ev_entry.1.insert(vh);
                }

                ref_visitors.entry(guard.referrer_host[i]).or_default().insert(vh);
                let utm_id = guard.utm_source[i];
                if !guard.utm_dict.resolve(utm_id).is_empty() {
                    utm_visitors.entry(utm_id).or_default().insert(vh);
                }
                browser_visitors.entry(guard.browser[i]).or_default().insert(vh);
                os_visitors.entry(guard.os[i]).or_default().insert(vh);
                device_visitors.entry(guard.device[i]).or_default().insert(vh);
                country_visitors.entry(guard.country[i]).or_default().insert(vh);

                if let Some(dt) = DateTime::from_timestamp(ts, 0) {
                    let bkey = if hourly {
                        dt.format("%Y-%m-%d %H:00").to_string()
                    } else {
                        dt.format("%Y-%m-%d").to_string()
                    };
                    if let Some(&bidx) = bucket_index.get(&bkey) {
                        bucket_visitors[bidx].insert(vh);
                        if is_pv {
                            bucket_pageviews[bidx] += 1;
                        }
                    }
                }
            }
        }

        let unique_visitors = all_visitors.len() as u64;
        let views_per_visit = if unique_visitors > 0 {
            total_pageviews as f64 / unique_visitors as f64
        } else {
            0.0
        };

        // Bounce rate & avg session duration
        let mut bounced_visitors: HashSet<u64> = HashSet::new();
        let mut page_bounces: HashMap<u32, u64> = HashMap::new();
        let mut duration_sum: i64 = 0;
        let mut duration_count: u64 = 0;

        for (vh, (pv_count, min_ts, max_ts, first_path)) in &visitor_sessions {
            if *pv_count <= 1 {
                bounced_visitors.insert(*vh);
                if let Some(pid) = first_path {
                    *page_bounces.entry(*pid).or_insert(0) += 1;
                }
            }
            // Cap single-visitor span per day to 1800s so multi-day revisits don't skew avg duration
            let span = (max_ts - min_ts).clamp(0, 1800);
            if span > 0 {
                duration_sum += span;
                duration_count += 1;
            }
        }

        let bounce_rate = if unique_visitors > 0 {
            (bounced_visitors.len() as f64 / unique_visitors as f64) * 100.0
        } else {
            0.0
        };

        let avg_session_duration_sec = if duration_count > 0 {
            duration_sum as f64 / duration_count as f64
        } else {
            0.0
        };

        // Build series
        let series: Vec<SeriesPoint> = bucket_keys
            .into_iter()
            .enumerate()
            .map(|(idx, (bucket, label))| SeriesPoint {
                bucket,
                label,
                visitors: bucket_visitors[idx].len() as u64,
                pageviews: bucket_pageviews[idx],
            })
            .collect();

        // Top pages
        let mut top_pages: Vec<PageStat> = page_visitors
            .into_iter()
            .map(|(pid, vset)| {
                let visitors = vset.len() as u64;
                let views = *page_views.get(&pid).unwrap_or(&0);
                let bounces = *page_bounces.get(&pid).unwrap_or(&0);
                let br = if visitors > 0 {
                    (bounces as f64 / visitors as f64) * 100.0
                } else {
                    0.0
                };
                PageStat {
                    path: guard.path_dict.resolve(pid).to_string(),
                    visitors,
                    views,
                    bounce_rate: br,
                }
            })
            .collect();
        top_pages.sort_by(|a, b| b.visitors.cmp(&a.visitors).then_with(|| b.views.cmp(&a.views)));
        top_pages.truncate(12);

        let top_referrers = build_dimension_stats(ref_visitors, &guard.ref_dict, unique_visitors, 10);
        let utm_sources = build_dimension_stats(utm_visitors, &guard.utm_dict, unique_visitors, 10);
        let browsers = build_dimension_stats(browser_visitors, &guard.browser_dict, unique_visitors, 8);
        let os = build_dimension_stats(os_visitors, &guard.os_dict, unique_visitors, 8);
        let devices = build_dimension_stats(device_visitors, &guard.device_dict, unique_visitors, 6);
        let countries = build_dimension_stats(country_visitors, &guard.country_dict, unique_visitors, 10);

        let mut custom_events: Vec<CustomEventStat> = custom_event_counts
            .into_iter()
            .map(|(eid, (count, vset))| CustomEventStat {
                name: guard.event_dict.resolve(eid).to_string(),
                count,
                visitors: vset.len() as u64,
            })
            .collect();
        custom_events.sort_by_key(|a| std::cmp::Reverse(a.count));
        custom_events.truncate(10);

        // Evaluate sequential plugin funnels
        let funnels = evaluate_funnels(&guard, &matched_indices, plugins.funnel_definitions());

        let active_visitors = active_set.len() as u64;
        let spike_alert = plugins.evaluate_spike_alert(active_visitors);
        let partition_count = guard.partitions.len();
        let total_rows = guard.len();
        drop(guard);

        let query_ms = start.elapsed().as_secs_f64() * 1000.0;

        StatsResponse {
            site: site.to_string(),
            range: canonical_range.to_string(),
            query_ms,
            unique_visitors,
            pageviews: total_pageviews,
            custom_events_total,
            views_per_visit,
            bounce_rate,
            avg_session_duration_sec,
            active_visitors,
            series,
            top_pages,
            top_referrers,
            utm_sources,
            browsers,
            os,
            devices,
            countries,
            custom_events,
            funnels,
            spike_alert,
            plugin_metrics: plugins.metrics(),
            compliance: ComplianceStatus {
                cookies_set: 0,
                raw_ips_stored: 0,
                tracker_bytes: TRACKER_JS.len(),
                salt_rotation: "Daily 256-bit RAM-only (UTC)".to_string(),
                respect_dnt: compliance_ctx.respect_dnt,
                clickhouse_enabled: compliance_ctx.clickhouse_enabled,
                partition_count,
                total_rows,
            },
        }
    }

    /// Deterministically seeds 14 days (~2,500 events) of realistic developer-site analytics
    /// for `demo.ghostmetrics.local` when the database is empty or requested explicitly.
    pub fn seed_demo_data(&self) -> io::Result<usize> {
        let now = Utc::now().timestamp();
        let site = "demo.ghostmetrics.local";
        let mut rng = XorShift64(0x6768_6f73_746d_6574);
        let mut events: Vec<EventRecord> = Vec::with_capacity(2800);

        let referrers = [
            "Direct",
            "github.com",
            "news.ycombinator.com",
            "lobste.rs",
            "duckduckgo.com",
            "reddit.com",
            "dev.to",
            "x.com",
        ];
        let utms = ["", "", "", "hackernews", "github_readme", "newsletter", "launch_post"];
        let browsers = ["Chrome", "Firefox", "Safari", "Edge", "Opera"];
        let os_list = ["macOS", "Linux", "Windows", "iOS", "Android"];
        let countries = ["US", "DE", "GB", "CA", "FR", "NL", "JP", "SG", "AU", "SE"];
        let secondary_pages = [
            "/docs/getting-started",
            "/docs/clickhouse",
            "/blog/no-cookie-architecture",
            "/benchmarks",
            "/plugins",
            "/changelog",
        ];

        // 14 days of organic daily traffic + realistic funnel journeys
        for day_offset in (0..14).rev() {
            let day_base = now - (day_offset * 86_400);
            // Gentle upward growth trend with realistic weekday/weekend rhythm
            let visitors_today = 52 + ((14 - day_offset) as usize * 3) + (rng.next_usize(18));

            for v_idx in 0..visitors_today {
                let vh = format!("{:016x}", rng.next_u64());
                let sec_in_day = if day_offset == 0 {
                    // Spread today's visitors up to right now, keeping a cluster in the last 5 minutes
                    if v_idx < 7 {
                        now - (rng.next_u64() % 260) as i64
                    } else {
                        now - (rng.next_u64() % 43_200) as i64
                    }
                } else {
                    day_base - (rng.next_u64() % 82_000) as i64
                };

                let ref_host = referrers[rng.weighted_idx(&[30, 24, 18, 8, 8, 5, 4, 3])];
                let utm = utms[rng.next_usize(utms.len())];
                let browser = browsers[rng.weighted_idx(&[46, 22, 18, 10, 4])];
                let os = os_list[rng.weighted_idx(&[34, 24, 22, 12, 8])];
                let device = match os {
                    "iOS" | "Android" => {
                        if rng.next_usize(10) == 0 {
                            "Tablet"
                        } else {
                            "Mobile"
                        }
                    }
                    _ => "Desktop",
                };
                let country = countries[rng.weighted_idx(&[36, 14, 11, 8, 7, 6, 5, 5, 4, 4])];

                let mut push_ev = |ts: i64, event_name: &str, path: &str| {
                    events.push(EventRecord {
                        ts,
                        site_id: site.to_string(),
                        visitor_hash: vh.clone(),
                        event_name: event_name.to_string(),
                        path: path.to_string(),
                        referrer_host: ref_host.to_string(),
                        utm_source: utm.to_string(),
                        country: country.to_string(),
                        browser: browser.to_string(),
                        os: os.to_string(),
                        device: device.to_string(),
                    });
                };

                // Step 1: Landing visit
                push_ev(sec_in_day, "pageview", "/");

                // ~34% bounce on landing page; remaining explore docs/pricing/funnel
                let roll = rng.next_usize(100);
                if roll < 34 {
                    continue;
                }

                // Explore a docs or blog page
                let p2 = secondary_pages[rng.next_usize(secondary_pages.len())];
                push_ev(sec_in_day + 28 + (rng.next_u64() % 60) as i64, "pageview", p2);

                if rng.next_usize(100) < 28 {
                    push_ev(
                        sec_in_day + 75 + (rng.next_u64() % 40) as i64,
                        "cli_install_copied",
                        p2,
                    );
                }

                // Step 2: Pricing inspection (~42% of all visitors)
                if roll >= 58 {
                    let t_pricing = sec_in_day + 95 + (rng.next_u64() % 90) as i64;
                    push_ev(t_pricing, "pageview", "/pricing");

                    // Step 3: Signup started (~22% of all visitors)
                    if roll >= 78 {
                        let t_signup = t_pricing + 45 + (rng.next_u64() % 80) as i64;
                        push_ev(t_signup, "pageview", "/signup");

                        // Step 4: Account created (~11% of all visitors)
                        if roll >= 89 {
                            let t_done = t_signup + 30 + (rng.next_u64() % 70) as i64;
                            push_ev(t_done, "signup_completed", "/signup");
                        }
                    }
                } else if rng.next_usize(100) < 18 {
                    push_ev(
                        sec_in_day + 110,
                        "clickhouse_sql_exported",
                        "/docs/clickhouse",
                    );
                }
            }
        }

        self.append_batch(&events)
    }
}

fn build_dimension_stats(
    map: HashMap<u32, HashSet<u64>>,
    dict: &StringDict,
    total_visitors: u64,
    limit: usize,
) -> Vec<DimensionStat> {
    let mut rows: Vec<DimensionStat> = map
        .into_iter()
        .map(|(id, vset)| {
            let visitors = vset.len() as u64;
            let share = if total_visitors > 0 {
                (visitors as f64 / total_visitors as f64) * 100.0
            } else {
                0.0
            };
            DimensionStat {
                name: dict.resolve(id).to_string(),
                visitors,
                share,
            }
        })
        .collect();
    rows.sort_by(|a, b| b.visitors.cmp(&a.visitors).then_with(|| a.name.cmp(&b.name)));
    rows.truncate(limit);
    rows
}

/// Evaluates plugin-defined funnels sequentially per visitor across all matched rows.
fn evaluate_funnels(
    table: &ColumnarTable,
    matched_indices: &[usize],
    definitions: &[FunnelDefinition],
) -> Vec<FunnelResult> {
    if definitions.is_empty() {
        return Vec::new();
    }

    // Group events by visitor_hash sorted by timestamp ascending
    let mut per_visitor: HashMap<u64, Vec<(i64, u32, u32)>> = HashMap::new();
    for &idx in matched_indices {
        per_visitor
            .entry(table.visitor_hash[idx])
            .or_default()
            .push((table.ts[idx], table.event_name[idx], table.path[idx]));
    }
    for events in per_visitor.values_mut() {
        events.sort_unstable_by_key(|(ts, _, _)| *ts);
    }

    let mut results = Vec::with_capacity(definitions.len());
    for def in definitions {
        let mut step_counts = vec![0u64; def.steps.len()];
        let step_event_ids: Vec<Option<u32>> = def
            .steps
            .iter()
            .map(|s| table.event_dict.get_id(&s.event_name))
            .collect();

        for events in per_visitor.values() {
            let mut cursor = 0usize;
            for (step_idx, step) in def.steps.iter().enumerate() {
                let target_eid = match step_event_ids[step_idx] {
                    Some(id) => id,
                    None => break,
                };
                let mut found_pos = None;
                for (pos, &(_, eid, pid)) in events.iter().enumerate().skip(cursor) {
                    if eid != target_eid {
                        continue;
                    }
                    let path_matches = match &step.path_prefix {
                        None => true,
                        Some(prefix) if prefix == "/" => table.path_dict.resolve(pid) == "/",
                        Some(prefix) => table.path_dict.resolve(pid).starts_with(prefix),
                    };
                    if path_matches {
                        found_pos = Some(pos);
                        break;
                    }
                }
                if let Some(pos) = found_pos {
                    step_counts[step_idx] += 1;
                    cursor = pos;
                } else {
                    break;
                }
            }
        }

        let top_count = step_counts.first().copied().unwrap_or(0);
        let last_count = step_counts.last().copied().unwrap_or(0);
        let overall = if top_count > 0 {
            (last_count as f64 / top_count as f64) * 100.0
        } else {
            0.0
        };

        let steps = def
            .steps
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let visitors = step_counts[i];
                let conversion_rate = if top_count > 0 {
                    (visitors as f64 / top_count as f64) * 100.0
                } else {
                    0.0
                };
                let matcher = match &s.path_prefix {
                    Some(p) => format!("{}:{}", s.event_name, p),
                    None => s.event_name.clone(),
                };
                FunnelStepResult {
                    label: s.label.clone(),
                    matcher,
                    visitors,
                    conversion_rate,
                }
            })
            .collect();

        results.push(FunnelResult {
            plugin_id: def.plugin_id.clone(),
            name: def.name.clone(),
            overall_conversion: overall,
            steps,
        });
    }

    results
}

pub fn parse_range(range: &str) -> (&'static str, bool, usize, i64) {
    match range.trim().to_ascii_lowercase().as_str() {
        "24h" | "1d" => ("24h", true, 24, 86_400),
        "30d" => ("30d", false, 30, 30 * 86_400),
        "90d" => ("90d", false, 90, 90 * 86_400),
        _ => ("7d", false, 7, 7 * 86_400),
    }
}

pub fn range_to_days(range: &str) -> i64 {
    match range.trim().to_ascii_lowercase().as_str() {
        "24h" | "1d" => 1,
        "30d" => 30,
        "90d" => 90,
        _ => 7,
    }
}

fn partition_day_from_ts(ts: i64) -> String {
    Utc.timestamp_opt(ts, 0)
        .single()
        .unwrap_or_else(Utc::now)
        .format("%Y-%m-%d")
        .to_string()
}

struct XorShift64(u64);

impl XorShift64 {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn next_usize(&mut self, bound: usize) -> usize {
        (self.next_u64() as usize) % bound.max(1)
    }

    fn weighted_idx(&mut self, weights: &[usize]) -> usize {
        let total: usize = weights.iter().sum();
        let mut pick = self.next_usize(total);
        for (idx, &w) in weights.iter().enumerate() {
            if pick < w {
                return idx;
            }
            pick -= w;
        }
        weights.len().saturating_sub(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::load_embedded_manifests;

    fn temp_dir(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let nanos = Utc::now().timestamp_nanos_opt().unwrap_or(0);
        p.push(format!("ghostmetrics-test-{name}-{nanos}"));
        p
    }

    #[test]
    fn columnar_store_persists_partitions_and_computes_exact_olap_metrics() {
        let dir = temp_dir("olap");
        let plugins = PluginEngine::from_manifests(load_embedded_manifests().unwrap());
        let now = Utc::now().timestamp();

        {
            let store = ColumnarStore::open(&dir).unwrap();
            // Visitor A: completes entire 4-step SaaS funnel (not bounced)
            for (offset, ev_name, path) in [
                (-120, "pageview", "/"),
                (-90, "pageview", "/pricing"),
                (-60, "pageview", "/signup"),
                (-30, "signup_completed", "/signup"),
            ] {
                store
                    .append(EventRecord {
                        ts: now + offset,
                        site_id: "acme.dev".into(),
                        visitor_hash: "00000000000000aa".into(),
                        event_name: ev_name.into(),
                        path: path.into(),
                        referrer_host: "github.com".into(),
                        utm_source: "launch".into(),
                        country: "US".into(),
                        browser: "Firefox".into(),
                        os: "Linux".into(),
                        device: "Desktop".into(),
                    })
                    .unwrap();
            }

            // Visitor B: single pageview bounce
            store
                .append(EventRecord {
                    ts: now - 40,
                    site_id: "acme.dev".into(),
                    visitor_hash: "00000000000000bb".into(),
                    event_name: "pageview".into(),
                    path: "/".into(),
                    referrer_host: "Direct".into(),
                    utm_source: "".into(),
                    country: "DE".into(),
                    browser: "Chrome".into(),
                    os: "macOS".into(),
                    device: "Desktop".into(),
                })
                .unwrap();
        }

        // Re-open store from disk partitions to verify durable reload
        let reopened = ColumnarStore::open(&dir).unwrap();
        assert_eq!(reopened.total_rows(), 5);
        assert_eq!(reopened.partition_count(), 1);

        let stats = reopened.query_stats(
            "acme.dev",
            "7d",
            &plugins,
            ComplianceContext {
                respect_dnt: true,
                clickhouse_enabled: false,
            },
        );

        assert_eq!(stats.unique_visitors, 2);
        assert_eq!(stats.pageviews, 4);
        assert_eq!(stats.custom_events_total, 1);
        assert_eq!(stats.active_visitors, 2);
        assert!((stats.bounce_rate - 50.0).abs() < 0.01);
        assert!((stats.views_per_visit - 2.0).abs() < 0.01);
        assert_eq!(stats.compliance.cookies_set, 0);
        assert_eq!(stats.compliance.raw_ips_stored, 0);

        // Funnel check: 2 landed on `/`, 1 hit `/pricing`, 1 hit `/signup`, 1 `signup_completed`
        assert_eq!(stats.funnels.len(), 1);
        let f = &stats.funnels[0];
        assert_eq!(f.steps[0].visitors, 2);
        assert_eq!(f.steps[1].visitors, 1);
        assert_eq!(f.steps[2].visitors, 1);
        assert_eq!(f.steps[3].visitors, 1);
        assert!((f.overall_conversion - 50.0).abs() < 0.01);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn demo_seeder_generates_realistic_multi_day_dataset() {
        let dir = temp_dir("demo");
        let store = ColumnarStore::open(&dir).unwrap();
        let inserted = store.seed_demo_data().unwrap();
        assert!(inserted > 1500, "expected >1500 seeded events, got {inserted}");

        let plugins = PluginEngine::from_manifests(load_embedded_manifests().unwrap());
        let stats = store.query_stats(
            "demo.ghostmetrics.local",
            "7d",
            &plugins,
            ComplianceContext {
                respect_dnt: true,
                clickhouse_enabled: false,
            },
        );
        assert!(stats.unique_visitors > 200);
        assert!(stats.pageviews > stats.unique_visitors);
        assert!(stats.active_visitors >= 1);
        assert!(stats.query_ms < 250.0);

        let _ = fs::remove_dir_all(&dir);
    }
}
