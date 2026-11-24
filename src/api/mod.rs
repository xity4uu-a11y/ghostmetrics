use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, FromRequestParts, Query, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_TYPE, HeaderName, HeaderValue};
use axum::http::request::Parts;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use futures_util::stream::Stream;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::set_header::SetResponseHeaderLayer;

use crate::plugins::{PluginEngine, PluginManifest, PluginMetrics};
use crate::privacy::{
    extract_referrer_host, is_bot, normalize_site, parse_user_agent, sanitize_csv_cell,
    scrub_url_path, SaltManager,
};
use crate::storage::clickhouse::{export_clickhouse_sql, ClickHouseBridge};
use crate::storage::columnar::{
    range_to_days, ColumnarStore, ComplianceContext, EventRecord, StatsResponse,
};
use crate::{ALPINE_JS, APP_CSS, INDEX_HTML, TRACKER_JS, VERSION};

const MAX_EVENT_BODY_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealtimeHit {
    pub site: String,
    pub event_name: String,
    pub path: String,
    pub browser: String,
    pub country: String,
    pub ts: i64,
}

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<ColumnarStore>,
    pub salt: Arc<SaltManager>,
    pub plugins: Arc<PluginEngine>,
    pub clickhouse: Option<Arc<ClickHouseBridge>>,
    pub realtime_tx: broadcast::Sender<RealtimeHit>,
    pub respect_dnt: bool,
    pub admin_token: Option<String>,
}

impl AppState {
    pub fn new(
        store: Arc<ColumnarStore>,
        plugins: Arc<PluginEngine>,
        clickhouse: Option<Arc<ClickHouseBridge>>,
        respect_dnt: bool,
        admin_token: Option<String>,
    ) -> Self {
        let (realtime_tx, _) = broadcast::channel(512);
        Self {
            store,
            salt: Arc::new(SaltManager::new()),
            plugins,
            clickhouse,
            realtime_tx,
            respect_dnt,
            admin_token,
        }
    }

    fn compliance_ctx(&self) -> ComplianceContext {
        ComplianceContext {
            respect_dnt: self.respect_dnt,
            clickhouse_enabled: self.clickhouse.is_some(),
        }
    }

    fn check_admin(&self, headers: &HeaderMap) -> bool {
        let Some(expected) = &self.admin_token else {
            return true;
        };
        if expected.is_empty() {
            return true;
        }
        headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .map(|token| constant_time_eq(token.as_bytes(), expected.as_bytes()))
            .unwrap_or(false)
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Extracts transient client IP in RAM only for daily-salted SHA-256 hashing.
/// Never persisted to disk or emitted in logs/responses.
struct TransientClientIp(String);

impl<S> FromRequestParts<S> for TransientClientIp
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        if let Some(ip) = header_str(&parts.headers, "cf-connecting-ip") {
            return Ok(Self(ip.to_string()));
        }
        if let Some(xff) = header_str(&parts.headers, "x-forwarded-for") {
            if let Some(first) = xff.split(',').next().map(str::trim) {
                if !first.is_empty() {
                    return Ok(Self(first.to_string()));
                }
            }
        }
        if let Some(ip) = header_str(&parts.headers, "x-real-ip") {
            return Ok(Self(ip.to_string()));
        }
        if let Some(ConnectInfo(addr)) = parts.extensions.get::<ConnectInfo<SocketAddr>>() {
            return Ok(Self(addr.ip().to_string()));
        }
        Ok(Self("127.0.0.1".to_string()))
    }
}

pub fn build_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(Any);

    Router::new()
        .route("/", get(serve_index))
        .route("/ghost.js", get(serve_tracker_js))
        .route("/assets/alpine.min.js", get(serve_alpine_js))
        .route("/assets/app.css", get(serve_app_css))
        .route("/api/event", post(ingest_event))
        .route("/api/stats", get(get_stats))
        .route("/api/realtime", get(realtime_sse))
        .route("/api/sites", get(list_sites).post(create_site))
        .route("/api/plugins", get(list_plugins))
        .route("/api/demo/seed", post(seed_demo))
        .route("/api/export/csv", get(export_csv))
        .route("/api/export/clickhouse.sql", get(export_clickhouse))
        .route("/api/export/digest.md", get(export_digest))
        .route("/healthz", get(healthz))
        .with_state(state)
        .layer(CompressionLayer::new())
        .layer(cors)
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static("interest-cohort=(), browsing-topics=()"),
        ))
}

async fn serve_index() -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, "text/html; charset=utf-8"),
            (CACHE_CONTROL, "no-cache"),
        ],
        INDEX_HTML,
    )
}

async fn serve_tracker_js() -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, "application/javascript; charset=utf-8"),
            (CACHE_CONTROL, "public, max-age=86400"),
        ],
        TRACKER_JS,
    )
}

async fn serve_alpine_js() -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, "application/javascript; charset=utf-8"),
            (CACHE_CONTROL, "public, max-age=604800"),
        ],
        ALPINE_JS,
    )
}

async fn serve_app_css() -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, "text/css; charset=utf-8"),
            (CACHE_CONTROL, "public, max-age=86400"),
        ],
        APP_CSS,
    )
}

#[derive(Debug, Deserialize)]
struct IngestPayload {
    site: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default, rename = "ref")]
    referrer: Option<String>,
    #[serde(default)]
    utm_source: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    props: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Serialize)]
struct IngestResponse {
    accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
}

async fn ingest_event(
    State(state): State<AppState>,
    TransientClientIp(client_ip): TransientClientIp,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if body.is_empty() || body.len() > MAX_EVENT_BODY_BYTES {
        return (
            StatusCode::BAD_REQUEST,
            Json(IngestResponse {
                accepted: false,
                reason: Some("invalid_payload_size"),
            }),
        )
            .into_response();
    }

    if state.respect_dnt && is_dnt_or_gpc(&headers) {
        return (
            StatusCode::ACCEPTED,
            Json(IngestResponse {
                accepted: false,
                reason: Some("dnt_respected"),
            }),
        )
            .into_response();
    }

    let user_agent = header_str(&headers, "user-agent").unwrap_or("");
    if is_bot(user_agent) {
        return (
            StatusCode::ACCEPTED,
            Json(IngestResponse {
                accepted: false,
                reason: Some("bot_filtered"),
            }),
        )
            .into_response();
    }

    // Accepts both `application/json` and `text/plain` sent by `navigator.sendBeacon`
    let payload: IngestPayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(IngestResponse {
                    accepted: false,
                    reason: Some("malformed_json"),
                }),
            )
                .into_response();
        }
    };

    let Some(site_id) = normalize_site(&payload.site) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(IngestResponse {
                accepted: false,
                reason: Some("invalid_site"),
            }),
        )
            .into_response();
    };

    let ref_host = extract_referrer_host(payload.referrer.as_deref().unwrap_or(""), &site_id);
    if state.plugins.is_spam_referrer(&ref_host) {
        return (
            StatusCode::ACCEPTED,
            Json(IngestResponse {
                accepted: false,
                reason: Some("spam_referrer_blocked"),
            }),
        )
            .into_response();
    }

    let pii_rules = state.plugins.pii_rules();
    let (clean_path, redactions) = scrub_url_path(
        payload.url.as_deref().unwrap_or("/"),
        &pii_rules.strip_query_params,
        pii_rules.redact_uuid_segments,
        pii_rules.redact_email_segments,
        &pii_rules.redact_numeric_segments_after,
    );
    state.plugins.record_pii_scrubbed(redactions);

    let event_name = sanitize_event_name(payload.name.as_deref().unwrap_or("pageview"));
    let utm_source = sanitize_short_tag(payload.utm_source.as_deref().unwrap_or(""));
    let client = parse_user_agent(user_agent);

    let country = header_str(&headers, "cf-ipcountry")
        .or_else(|| header_str(&headers, "x-country-code"))
        .or(payload.country.as_deref())
        .map(sanitize_country)
        .unwrap_or_else(|| "XX".to_string());

    // Hash visitor transiently in RAM using daily rotating 256-bit salt; raw IP is discarded immediately.
    let (visitor_hash, _) = state.salt.visitor_hash(&site_id, &client_ip, user_agent);
    let ts = Utc::now().timestamp();

    let record = EventRecord {
        ts,
        site_id: site_id.clone(),
        visitor_hash,
        event_name: event_name.clone(),
        path: clean_path.clone(),
        referrer_host: ref_host,
        utm_source,
        country: country.clone(),
        browser: client.browser.to_string(),
        os: client.os.to_string(),
        device: client.device.to_string(),
    };

    if let Err(err) = state.store.append(record.clone()) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "accepted": false, "error": err.to_string() })),
        )
            .into_response();
    }

    if let Some(ch) = &state.clickhouse {
        ch.enqueue(record);
    }

    let _ = state.realtime_tx.send(RealtimeHit {
        site: site_id,
        event_name,
        path: clean_path,
        browser: client.browser.to_string(),
        country,
        ts,
    });

    (
        StatusCode::ACCEPTED,
        Json(IngestResponse {
            accepted: true,
            reason: None,
        }),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
struct StatsQuery {
    site: Option<String>,
    range: Option<String>,
}

async fn get_stats(
    State(state): State<AppState>,
    Query(q): Query<StatsQuery>,
) -> Json<StatsResponse> {
    let site = resolve_site_param(&state, q.site.as_deref());
    let range = q.range.as_deref().unwrap_or("7d");
    let stats = state
        .store
        .query_stats(&site, range, &state.plugins, state.compliance_ctx());
    Json(stats)
}

async fn realtime_sse(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>>> {
    let rx = state.realtime_tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|item| match item {
        Ok(hit) => serde_json::to_string(&hit)
            .ok()
            .map(|json| Ok(SseEvent::default().event("hit").data(json))),
        Err(_) => None,
    });

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keepalive"),
    )
}

async fn list_sites(State(state): State<AppState>) -> Json<serde_json::Value> {
    let mut sites = state.store.list_sites();
    if sites.is_empty() {
        sites.push("demo.ghostmetrics.local".to_string());
    }
    Json(serde_json::json!({ "sites": sites }))
}

#[derive(Debug, Deserialize)]
struct CreateSitePayload {
    site: String,
}

async fn create_site(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateSitePayload>,
) -> Response {
    if !state.check_admin(&headers) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "unauthorized" })),
        )
            .into_response();
    }

    let Some(site) = normalize_site(&payload.site) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid_site_domain" })),
        )
            .into_response();
    };

    match state.store.register_site(&site) {
        Ok(()) => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "site": site, "created": true })),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": err.to_string() })),
        )
            .into_response(),
    }
}

#[derive(Serialize)]
struct PluginsResponse<'a> {
    plugins: &'a [PluginManifest],
    metrics: PluginMetrics,
}

async fn list_plugins(State(state): State<AppState>) -> Json<serde_json::Value> {
    let resp = PluginsResponse {
        plugins: state.plugins.manifests(),
        metrics: state.plugins.metrics(),
    };
    Json(serde_json::to_value(resp).unwrap_or_else(|_| serde_json::json!({ "plugins": [] })))
}

async fn seed_demo(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !state.check_admin(&headers) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "unauthorized" })),
        )
            .into_response();
    }
    match state.store.seed_demo_data() {
        Ok(inserted) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "seeded": true,
                "site": "demo.ghostmetrics.local",
                "events_inserted": inserted
            })),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": err.to_string() })),
        )
            .into_response(),
    }
}

async fn export_csv(State(state): State<AppState>, Query(q): Query<StatsQuery>) -> impl IntoResponse {
    let site = q.site.as_deref().and_then(normalize_site);
    let days = q.range.as_deref().map(range_to_days);
    let events = state.store.export_events(site.as_deref(), days);

    let mut csv = String::from(
        "timestamp_utc,site_id,visitor_hash,event_name,path,referrer_host,utm_source,country,browser,os,device\n",
    );
    for ev in &events {
        let ts_iso = chrono::DateTime::from_timestamp(ev.ts, 0)
            .map(|d| d.to_rfc3339())
            .unwrap_or_default();
        let cols = [
            sanitize_csv_cell(&ts_iso),
            sanitize_csv_cell(&ev.site_id),
            sanitize_csv_cell(&ev.visitor_hash),
            sanitize_csv_cell(&ev.event_name),
            sanitize_csv_cell(&ev.path),
            sanitize_csv_cell(&ev.referrer_host),
            sanitize_csv_cell(&ev.utm_source),
            sanitize_csv_cell(&ev.country),
            sanitize_csv_cell(&ev.browser),
            sanitize_csv_cell(&ev.os),
            sanitize_csv_cell(&ev.device),
        ];
        csv.push_str(&cols.join(","));
        csv.push('\n');
    }

    (
        [
            (CONTENT_TYPE, "text/csv; charset=utf-8"),
            (
                CONTENT_DISPOSITION,
                "attachment; filename=\"ghostmetrics-export.csv\"",
            ),
        ],
        csv,
    )
}

async fn export_clickhouse(
    State(state): State<AppState>,
    Query(q): Query<StatsQuery>,
) -> impl IntoResponse {
    let site = q.site.as_deref().and_then(normalize_site);
    let events = state.store.export_events(site.as_deref(), None);
    let sql = export_clickhouse_sql(&events);
    (
        [
            (CONTENT_TYPE, "application/sql; charset=utf-8"),
            (
                CONTENT_DISPOSITION,
                "attachment; filename=\"ghostmetrics-clickhouse.sql\"",
            ),
        ],
        sql,
    )
}

async fn export_digest(
    State(state): State<AppState>,
    Query(q): Query<StatsQuery>,
) -> impl IntoResponse {
    let site = resolve_site_param(&state, q.site.as_deref());
    let range = q.range.as_deref().unwrap_or("7d");
    let stats = state
        .store
        .query_stats(&site, range, &state.plugins, state.compliance_ctx());
    let md = state.plugins.render_digest_markdown(&stats);
    (
        [
            (CONTENT_TYPE, "text/markdown; charset=utf-8"),
            (
                CONTENT_DISPOSITION,
                "attachment; filename=\"ghostmetrics-digest.md\"",
            ),
        ],
        md,
    )
}

async fn healthz(State(state): State<AppState>) -> Json<serde_json::Value> {
    let ch_info = state.clickhouse.as_ref().map(|c| {
        serde_json::json!({
            "endpoint": c.endpoint_label(),
            "flushed_rows": c.flushed_rows(),
            "failed_batches": c.failed_batches()
        })
    });

    Json(serde_json::json!({
        "status": "ok",
        "version": VERSION,
        "cookies_set": 0,
        "raw_ips_stored": 0,
        "tracker_bytes": TRACKER_JS.len(),
        "total_rows": state.store.total_rows(),
        "partitions": state.store.partition_count(),
        "plugins_loaded": state.plugins.manifests().len(),
        "salt_utc_day": state.salt.current_utc_day().to_string(),
        "clickhouse_bridge": ch_info
    }))
}

fn resolve_site_param(state: &AppState, requested: Option<&str>) -> String {
    if let Some(s) = requested.and_then(normalize_site) {
        return s;
    }
    state
        .store
        .list_sites()
        .into_iter()
        .next()
        .unwrap_or_else(|| "demo.ghostmetrics.local".to_string())
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok()).map(str::trim)
}

fn is_dnt_or_gpc(headers: &HeaderMap) -> bool {
    header_str(headers, "dnt") == Some("1") || header_str(headers, "sec-gpc") == Some("1")
}

fn sanitize_event_name(raw: &str) -> String {
    let clean: String = raw
        .trim()
        .chars()
        .take(64)
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':'))
        .collect();
    if clean.is_empty() {
        "pageview".to_string()
    } else {
        clean
    }
}

fn sanitize_short_tag(raw: &str) -> String {
    raw.trim()
        .chars()
        .take(64)
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        .collect()
}

fn sanitize_country(raw: &str) -> String {
    let code: String = raw
        .trim()
        .chars()
        .filter(char::is_ascii_alphabetic)
        .take(2)
        .collect::<String>()
        .to_ascii_uppercase();
    if code.len() == 2 {
        code
    } else {
        "XX".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use crate::plugins::load_embedded_manifests;

    fn test_app(name: &str, admin_token: Option<String>) -> (Router, PathBuf) {
        let mut dir = std::env::temp_dir();
        let nanos = Utc::now().timestamp_nanos_opt().unwrap_or(0);
        dir.push(format!("ghostmetrics-api-{name}-{nanos}"));
        let store = Arc::new(ColumnarStore::open(&dir).unwrap());
        let plugins = Arc::new(PluginEngine::from_manifests(load_embedded_manifests().unwrap()));
        let state = AppState::new(store, plugins, None, true, admin_token);
        (build_router(state), dir)
    }

    async fn body_string(res: Response) -> String {
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn dashboard_tracker_and_assets_return_zero_cookies() {
        let (app, dir) = test_app("assets", None);

        for (uri, expected_ct) in [
            ("/", "text/html"),
            ("/ghost.js", "application/javascript"),
            ("/assets/alpine.min.js", "application/javascript"),
            ("/assets/app.css", "text/css"),
        ] {
            let res = app
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::OK, "route {uri} failed");
            assert!(
                res.headers().get("set-cookie").is_none(),
                "route {uri} must never emit Set-Cookie"
            );
            let ct = res
                .headers()
                .get(CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap();
            assert!(ct.contains(expected_ct), "unexpected content-type on {uri}: {ct}");

            if uri == "/ghost.js" {
                let script = body_string(res).await;
                assert!(
                    script.len() < 900,
                    "ghost.js must be < 900 bytes, got {}",
                    script.len()
                );
                assert!(!script.contains("cookie"));
                assert!(!script.contains("localStorage"));
            }
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn full_ingestion_privacy_plugin_and_export_pipeline() {
        let (app, dir) = test_app("pipeline", None);
        let browser_ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36";

        // 1. Valid sendBeacon (`text/plain`) pageview with PII query + UUID segment
        let beacon_body = serde_json::json!({
            "site": "app.example.test",
            "name": "pageview",
            "url": "/users/550e8400-e29b-41d4-a716-446655440000?email=leak@test.com&token=abc&utm_source=hn",
            "ref": "https://news.ycombinator.com/item?id=1"
        })
        .to_string();

        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/event")
                    .header("content-type", "text/plain;charset=UTF-8")
                    .header("user-agent", browser_ua)
                    .header("x-forwarded-for", "198.51.100.42")
                    .header("cf-ipcountry", "US")
                    .body(Body::from(beacon_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::ACCEPTED);
        assert!(res.headers().get("set-cookie").is_none());
        let txt = body_string(res).await;
        assert!(txt.contains("\"accepted\":true"));

        // 2. DNT request must be rejected cleanly
        let dnt_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/event")
                    .header("content-type", "application/json")
                    .header("user-agent", browser_ua)
                    .header("dnt", "1")
                    .body(Body::from(r#"{"site":"app.example.test","url":"/secret"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(dnt_res.status(), StatusCode::ACCEPTED);
        assert!(body_string(dnt_res).await.contains("dnt_respected"));

        // 3. Bot UA must be filtered
        let bot_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/event")
                    .header("content-type", "application/json")
                    .header("user-agent", "Googlebot/2.1")
                    .body(Body::from(r#"{"site":"app.example.test","url":"/"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(body_string(bot_res).await.contains("bot_filtered"));

        // 4. Spam referrer must be blocked by referrer-spam-shield plugin
        let spam_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/event")
                    .header("content-type", "application/json")
                    .header("user-agent", browser_ua)
                    .body(Body::from(
                        r#"{"site":"app.example.test","url":"/","ref":"https://semalt.com/spam"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(body_string(spam_res).await.contains("spam_referrer_blocked"));

        // 5. Query OLAP stats
        let stats_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/stats?site=app.example.test&range=7d")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(stats_res.status(), StatusCode::OK);
        let stats: StatsResponse = serde_json::from_str(&body_string(stats_res).await).unwrap();
        assert_eq!(stats.unique_visitors, 1);
        assert_eq!(stats.pageviews, 1);
        assert_eq!(stats.top_pages[0].path, "/users/[redacted]");
        assert_eq!(stats.plugin_metrics.spam_blocked, 1);
        assert!(stats.plugin_metrics.pii_scrubbed >= 3);
        assert_eq!(stats.compliance.cookies_set, 0);
        assert_eq!(stats.compliance.raw_ips_stored, 0);

        // 6. ClickHouse SQL export
        let sql_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/export/clickhouse.sql?site=app.example.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(sql_res.status(), StatusCode::OK);
        let sql = body_string(sql_res).await;
        assert!(sql.contains("ENGINE = MergeTree()"));
        assert!(sql.contains("FORMAT JSONEachRow"));
        assert!(!sql.contains("198.51.100.42"), "raw IP must NEVER appear in export");
        assert!(!sql.contains("leak@test.com"), "PII email must NEVER appear in export");

        // 7. Markdown digest export
        let md_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/export/digest.md?site=app.example.test&range=7d")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(md_res.status(), StatusCode::OK);
        let md = body_string(md_res).await;
        assert!(md.contains("GhostMetrics Analytics Digest"));
        assert!(md.contains("Privacy & No-Cookie Compliance Attestation"));

        // 8. CSV formula injection check
        let formula_ev = serde_json::json!({
            "site": "app.example.test",
            "name": "pageview",
            "url": "/=SUM(A1:A2)",
            "ref": ""
        })
        .to_string();
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/event")
                    .header("content-type", "application/json")
                    .header("user-agent", browser_ua)
                    .body(Body::from(formula_ev))
                    .unwrap(),
            )
            .await
            .unwrap();

        let csv_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/export/csv?site=app.example.test&range=7d")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(csv_res.status(), StatusCode::OK);
        let csv = body_string(csv_res).await;
        assert!(csv.contains("timestamp_utc,site_id,visitor_hash"));
        assert!(!csv.contains("198.51.100.42"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn admin_token_protects_site_creation() {
        let (app, dir) = test_app("auth", Some("unit-test-token-value".into()));

        let unauth = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/sites")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"site":"new.example.test"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

        let authed = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/sites")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer unit-test-token-value")
                    .body(Body::from(r#"{"site":"new.example.test"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authed.status(), StatusCode::CREATED);

        let _ = fs::remove_dir_all(&dir);
    }
}
