pub mod api;
pub mod cli;
pub mod plugins;
pub mod privacy;
pub mod storage;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub const TRACKER_JS: &str = include_str!("../web/ghost.js");
pub const INDEX_HTML: &str = include_str!("../web/index.html");
pub const APP_CSS: &str = include_str!("../web/app.css");
pub const ALPINE_JS: &str = include_str!("../web/alpine.min.js");
pub const CLICKHOUSE_SCHEMA_SQL: &str = include_str!("../schema/clickhouse.sql");
