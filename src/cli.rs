use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "ghostmetrics",
    version,
    about = "Privacy-first, zero-cookie web analytics in a single Rust binary with embedded columnar OLAP storage and ClickHouse bridge."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    #[command(flatten)]
    pub default_serve: ServeArgs,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Start the GhostMetrics HTTP server and Alpine.js dashboard (default).
    Serve(ServeArgs),

    /// Run a sub-millisecond OLAP rollup against local columnar partitions and print stats.
    Stats(StatsArgs),

    /// Export ClickHouse MergeTree DDL, MaterializedView, and JSONEachRow event payload.
    ExportClickhouse(ExportClickhouseArgs),

    /// Strictly validate all community JSON plugin manifests in a directory.
    ValidatePlugins(ValidatePluginsArgs),

    /// Print version, build target, and embedded tracker script byte size.
    Version,
}

#[derive(Debug, Clone, Args)]
pub struct ServeArgs {
    /// Bind address for the HTTP server.
    #[arg(long, default_value = "127.0.0.1:8080", env = "GHOSTMETRICS_ADDR")]
    pub addr: String,

    /// Directory storing UTC-day columnar partition files (.chcol).
    #[arg(long, default_value = "./ghostmetrics-data", env = "GHOSTMETRICS_DATA_DIR")]
    pub data_dir: PathBuf,

    /// Directory containing community JSON plugin manifests.
    #[arg(long, default_value = "./plugins", env = "GHOSTMETRICS_PLUGINS_DIR")]
    pub plugins_dir: PathBuf,

    /// Optional ClickHouse HTTP endpoint (e.g. http://127.0.0.1:8123) for async JSONEachRow mirroring.
    #[arg(long, env = "GHOSTMETRICS_CLICKHOUSE_URL")]
    pub clickhouse_url: Option<String>,

    /// Seed 14 days of realistic developer-site demo analytics if the store is empty.
    #[arg(long, default_value_t = false, env = "GHOSTMETRICS_SEED_DEMO")]
    pub seed_demo: bool,

    /// Optional bearer token protecting POST /api/sites and POST /api/demo/seed.
    #[arg(long, env = "GHOSTMETRICS_ADMIN_TOKEN")]
    pub admin_token: Option<String>,

    /// Honor browser DNT: 1 and Sec-GPC: 1 headers (true by default).
    #[arg(
        long,
        default_value_t = true,
        action = clap::ArgAction::Set,
        env = "GHOSTMETRICS_RESPECT_DNT"
    )]
    pub respect_dnt: bool,
}

#[derive(Debug, Args)]
pub struct StatsArgs {
    /// Directory storing UTC-day columnar partition files.
    #[arg(long, default_value = "./ghostmetrics-data", env = "GHOSTMETRICS_DATA_DIR")]
    pub data_dir: PathBuf,

    /// Directory containing community JSON plugin manifests.
    #[arg(long, default_value = "./plugins", env = "GHOSTMETRICS_PLUGINS_DIR")]
    pub plugins_dir: PathBuf,

    /// Target site domain (defaults to first tracked site).
    #[arg(long)]
    pub site: Option<String>,

    /// Query window: 24h, 7d, 30d, or 90d.
    #[arg(long, default_value = "7d")]
    pub range: String,

    /// Output full OLAP response as formatted JSON.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ExportClickhouseArgs {
    /// Directory storing UTC-day columnar partition files.
    #[arg(long, default_value = "./ghostmetrics-data", env = "GHOSTMETRICS_DATA_DIR")]
    pub data_dir: PathBuf,

    /// Optional site domain filter.
    #[arg(long)]
    pub site: Option<String>,

    /// Output SQL file path.
    #[arg(long, default_value = "./clickhouse-export.sql")]
    pub out: PathBuf,
}

#[derive(Debug, Args)]
pub struct ValidatePluginsArgs {
    /// Directory containing plugin JSON manifests.
    #[arg(long, default_value = "./plugins")]
    pub dir: PathBuf,
}
