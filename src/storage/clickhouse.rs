use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::{TimeZone, Utc};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{interval, timeout};

use crate::storage::columnar::EventRecord;
use crate::CLICKHOUSE_SCHEMA_SQL;

#[derive(Serialize)]
struct ClickHouseRow<'a> {
    ts: String,
    site_id: &'a str,
    visitor_hash: &'a str,
    event_name: &'a str,
    path: &'a str,
    referrer_host: &'a str,
    utm_source: &'a str,
    country: &'a str,
    browser: &'a str,
    os: &'a str,
    device: &'a str,
}

/// Formats events into newline-delimited ClickHouse `JSONEachRow` format.
pub fn format_json_each_row(events: &[EventRecord]) -> String {
    let mut out = String::with_capacity(events.len() * 180);
    for ev in events {
        let dt_str = Utc
            .timestamp_opt(ev.ts, 0)
            .single()
            .unwrap_or_else(Utc::now)
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        let row = ClickHouseRow {
            ts: dt_str,
            site_id: &ev.site_id,
            visitor_hash: &ev.visitor_hash,
            event_name: &ev.event_name,
            path: &ev.path,
            referrer_host: &ev.referrer_host,
            utm_source: &ev.utm_source,
            country: &ev.country,
            browser: &ev.browser,
            os: &ev.os,
            device: &ev.device,
        };
        if let Ok(line) = serde_json::to_string(&row) {
            out.push_str(&line);
            out.push('\n');
        }
    }
    out
}

/// Exports full ClickHouse `MergeTree` + `MaterializedView` DDL and `JSONEachRow` insert payload.
pub fn export_clickhouse_sql(events: &[EventRecord]) -> String {
    let mut sql = String::from(CLICKHOUSE_SCHEMA_SQL);
    if !sql.ends_with('\n') {
        sql.push('\n');
    }
    if !events.is_empty() {
        sql.push_str("\nINSERT INTO ghostmetrics_events FORMAT JSONEachRow\n");
        sql.push_str(&format_json_each_row(events));
        sql.push_str(";\n");
    }
    sql
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClickHouseEndpoint {
    pub host: String,
    pub port: u16,
    pub database: Option<String>,
}

impl ClickHouseEndpoint {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err("ClickHouse URL is empty".to_string());
        }
        let without_scheme = trimmed
            .strip_prefix("http://")
            .ok_or_else(|| {
                "ClickHouse bridge expects plain HTTP endpoint (e.g., http://127.0.0.1:8123)".to_string()
            })?;

        let (authority, path_part) = match without_scheme.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (without_scheme, None),
        };

        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => {
                let parsed_port = p
                    .parse::<u16>()
                    .map_err(|_| format!("Invalid ClickHouse port '{p}'"))?;
                (h.to_string(), parsed_port)
            }
            None => (authority.to_string(), 8123),
        };

        if host.is_empty() {
            return Err("ClickHouse host is empty".to_string());
        }

        let database = path_part
            .map(|p| p.trim_matches('/'))
            .filter(|p| !p.is_empty() && !p.starts_with('?'))
            .map(ToString::to_string);

        Ok(Self {
            host,
            port,
            database,
        })
    }

    pub fn socket_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Non-blocking ClickHouse HTTP/1.1 `JSONEachRow` batch flusher over pure-Tokio `TcpStream`.
///
/// Always operates asynchronously behind the local embedded columnar store so ingestion
/// latency is unaffected and the server continues cleanly if ClickHouse is temporarily offline.
pub struct ClickHouseBridge {
    endpoint: ClickHouseEndpoint,
    tx: mpsc::Sender<EventRecord>,
    flushed_rows: Arc<AtomicU64>,
    failed_batches: Arc<AtomicU64>,
}

impl ClickHouseBridge {
    pub fn spawn(url: &str) -> Result<Arc<Self>, String> {
        let endpoint = ClickHouseEndpoint::parse(url)?;
        let (tx, mut rx) = mpsc::channel::<EventRecord>(4096);
        let flushed_rows = Arc::new(AtomicU64::new(0));
        let failed_batches = Arc::new(AtomicU64::new(0));

        let bg_endpoint = endpoint.clone();
        let bg_flushed = Arc::clone(&flushed_rows);
        let bg_failed = Arc::clone(&failed_batches);

        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(2));
            let mut buffer: Vec<EventRecord> = Vec::with_capacity(128);

            loop {
                tokio::select! {
                    maybe_ev = rx.recv() => {
                        match maybe_ev {
                            Some(ev) => {
                                buffer.push(ev);
                                if buffer.len() >= 100 {
                                    flush_buffer(&bg_endpoint, &mut buffer, &bg_flushed, &bg_failed).await;
                                }
                            }
                            None => {
                                if !buffer.is_empty() {
                                    flush_buffer(&bg_endpoint, &mut buffer, &bg_flushed, &bg_failed).await;
                                }
                                break;
                            }
                        }
                    }
                    _ = ticker.tick() => {
                        if !buffer.is_empty() {
                            flush_buffer(&bg_endpoint, &mut buffer, &bg_flushed, &bg_failed).await;
                        }
                    }
                }
            }
        });

        Ok(Arc::new(Self {
            endpoint,
            tx,
            flushed_rows,
            failed_batches,
        }))
    }

    pub fn enqueue(&self, event: EventRecord) {
        let _ = self.tx.try_send(event);
    }

    pub fn endpoint_label(&self) -> String {
        format!("http://{}:{}", self.endpoint.host, self.endpoint.port)
    }

    pub fn flushed_rows(&self) -> u64 {
        self.flushed_rows.load(Ordering::Relaxed)
    }

    pub fn failed_batches(&self) -> u64 {
        self.failed_batches.load(Ordering::Relaxed)
    }
}

async fn flush_buffer(
    endpoint: &ClickHouseEndpoint,
    buffer: &mut Vec<EventRecord>,
    flushed_rows: &AtomicU64,
    failed_batches: &AtomicU64,
) {
    let count = buffer.len() as u64;
    let body = format_json_each_row(buffer);
    buffer.clear();

    match send_batch_http(endpoint, &body).await {
        Ok(()) => {
            flushed_rows.fetch_add(count, Ordering::Relaxed);
        }
        Err(_) => {
            failed_batches.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Pure-Rust HTTP/1.1 `POST /?query=INSERT+INTO+ghostmetrics_events+FORMAT+JSONEachRow` client.
pub async fn send_batch_http(endpoint: &ClickHouseEndpoint, payload: &str) -> Result<(), String> {
    let addr = endpoint.socket_addr();
    let mut stream = timeout(Duration::from_secs(2), TcpStream::connect(&addr))
        .await
        .map_err(|_| format!("ClickHouse connect timeout to {addr}"))?
        .map_err(|e| format!("ClickHouse connect failed to {addr}: {e}"))?;

    let db_prefix = match &endpoint.database {
        Some(db) => format!("database={db}&"),
        None => String::new(),
    };
    let target = format!(
        "/?{db_prefix}query=INSERT+INTO+ghostmetrics_events+FORMAT+JSONEachRow"
    );
    let body_bytes = payload.as_bytes();
    let request = format!(
        "POST {target} HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: application/x-ndjson\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        endpoint.host,
        endpoint.port,
        body_bytes.len()
    );

    timeout(Duration::from_secs(2), async {
        stream.write_all(request.as_bytes()).await?;
        stream.write_all(body_bytes).await?;
        stream.flush().await?;
        let mut resp = Vec::with_capacity(256);
        stream.read_to_end(&mut resp).await?;
        Ok::<Vec<u8>, std::io::Error>(resp)
    })
    .await
    .map_err(|_| "ClickHouse HTTP write/read timeout".to_string())?
    .map_err(|e| format!("ClickHouse IO error: {e}"))
    .and_then(|resp| {
        let head = String::from_utf8_lossy(&resp);
        let status_line = head.lines().next().unwrap_or("");
        if status_line.contains(" 200 ") || status_line.contains(" 204 ") {
            Ok(())
        } else {
            Err(format!("Unexpected ClickHouse HTTP status: {status_line}"))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn sample_event() -> EventRecord {
        EventRecord {
            ts: 1_760_000_000,
            site_id: "demo.ghostmetrics.local".into(),
            visitor_hash: "0123456789abcdef".into(),
            event_name: "pageview".into(),
            path: "/pricing".into(),
            referrer_host: "github.com".into(),
            utm_source: "readme".into(),
            country: "US".into(),
            browser: "Chrome".into(),
            os: "Linux".into(),
            device: "Desktop".into(),
        }
    }

    #[test]
    fn export_sql_contains_mergetree_and_jsoneachrow() {
        let sql = export_clickhouse_sql(&[sample_event()]);
        assert!(sql.contains("ENGINE = MergeTree()"));
        assert!(sql.contains("CREATE MATERIALIZED VIEW IF NOT EXISTS ghostmetrics_daily_stats_mv"));
        assert!(sql.contains("INSERT INTO ghostmetrics_events FORMAT JSONEachRow"));
        assert!(sql.contains("\"visitor_hash\":\"0123456789abcdef\""));
    }

    #[tokio::test]
    async fn http_bridge_posts_jsoneachrow_to_clickhouse_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = sock.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            sock.write_all(resp.as_bytes()).await.unwrap();
            req
        });

        let ep = ClickHouseEndpoint::parse(&format!("http://127.0.0.1:{}", addr.port())).unwrap();
        let payload = format_json_each_row(&[sample_event()]);
        send_batch_http(&ep, &payload).await.unwrap();

        let received = server.await.unwrap();
        assert!(received.starts_with("POST /?query=INSERT+INTO+ghostmetrics_events+FORMAT+JSONEachRow HTTP/1.1"));
        assert!(received.contains("\"site_id\":\"demo.ghostmetrics.local\""));
    }
}
