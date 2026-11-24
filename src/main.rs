use std::fs;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use tokio::net::TcpListener;

use ghostmetrics::api::{build_router, AppState};
use ghostmetrics::cli::{Cli, Command, ExportClickhouseArgs, ServeArgs, StatsArgs, ValidatePluginsArgs};
use ghostmetrics::plugins::{validate_directory, PluginEngine};
use ghostmetrics::storage::clickhouse::{export_clickhouse_sql, ClickHouseBridge};
use ghostmetrics::storage::columnar::{ColumnarStore, ComplianceContext};
use ghostmetrics::{TRACKER_JS, VERSION};

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    let result = match cli.command {
        Some(Command::Serve(args)) => run_serve(args).await,
        None => run_serve(cli.default_serve).await,
        Some(Command::Stats(args)) => run_stats(args),
        Some(Command::ExportClickhouse(args)) => run_export_clickhouse(args),
        Some(Command::ValidatePlugins(args)) => run_validate_plugins(args),
        Some(Command::Version) => {
            print_version();
            Ok(())
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::FAILURE
        }
    }
}

async fn run_serve(args: ServeArgs) -> Result<(), String> {
    let store = Arc::new(
        ColumnarStore::open(&args.data_dir)
            .map_err(|e| format!("failed to open columnar store at {}: {e}", args.data_dir.display()))?,
    );

    if args.seed_demo && store.total_rows() == 0 {
        let seeded = store
            .seed_demo_data()
            .map_err(|e| format!("failed to seed demo dataset: {e}"))?;
        println!(
            "GhostMetrics seeded {seeded} demo events across 14 days for demo.ghostmetrics.local"
        );
    }

    let plugins = Arc::new(
        PluginEngine::load_from_dir_or_embedded(&args.plugins_dir)
            .map_err(|errs| format!("plugin validation failed:\n  - {}", errs.join("\n  - ")))?,
    );

    let clickhouse = match args.clickhouse_url.as_deref() {
        Some(url) if !url.trim().is_empty() => Some(ClickHouseBridge::spawn(url)?),
        _ => None,
    };

    let state = AppState::new(
        Arc::clone(&store),
        Arc::clone(&plugins),
        clickhouse.clone(),
        args.respect_dnt,
        args.admin_token.clone(),
    );

    let app = build_router(state);
    let addr: SocketAddr = args
        .addr
        .parse()
        .map_err(|e| format!("invalid bind address '{}': {e}", args.addr))?;

    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| format!("failed to bind {addr}: {e}"))?;

    println!("GhostMetrics v{VERSION}");
    println!("  Dashboard:   http://{addr}/");
    println!("  Tracker JS:  http://{addr}/ghost.js ({} bytes raw, 0 cookies)", TRACKER_JS.len());
    println!("  Data Dir:    {} ({} rows, {} partitions)", args.data_dir.display(), store.total_rows(), store.partition_count());
    println!("  Plugins:     {} active", plugins.manifests().len());
    println!(
        "  ClickHouse:  {}",
        clickhouse
            .as_ref()
            .map(|c| c.endpoint_label())
            .unwrap_or_else(|| "embedded columnar (local)".to_string())
    );
    println!("  Privacy:     0 Set-Cookie headers | 0 raw IPs persisted | Daily RAM-only 256-bit salt");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .map_err(|e| format!("server exited with error: {e}"))
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    println!("\nGhostMetrics shutting down cleanly.");
}

fn run_stats(args: StatsArgs) -> Result<(), String> {
    let store = ColumnarStore::open(&args.data_dir)
        .map_err(|e| format!("failed to open columnar store: {e}"))?;
    let plugins = PluginEngine::load_from_dir_or_embedded(&args.plugins_dir)
        .map_err(|errs| errs.join("\n"))?;

    let site = args
        .site
        .or_else(|| store.list_sites().into_iter().next())
        .unwrap_or_else(|| "demo.ghostmetrics.local".to_string());

    let stats = store.query_stats(
        &site,
        &args.range,
        &plugins,
        ComplianceContext {
            respect_dnt: true,
            clickhouse_enabled: false,
        },
    );

    if args.json {
        let json = serde_json::to_string_pretty(&stats)
            .map_err(|e| format!("serialization failed: {e}"))?;
        println!("{json}");
        return Ok(());
    }

    println!("GhostMetrics OLAP Report");
    println!("------------------------------------------------------------");
    println!("Site:             {}", stats.site);
    println!("Window:           {}", stats.range);
    println!("OLAP Query Time:  {:.2} ms", stats.query_ms);
    println!("Unique Visitors:  {}", stats.unique_visitors);
    println!("Total Pageviews:  {}", stats.pageviews);
    println!("Custom Events:    {}", stats.custom_events_total);
    println!("Views / Visit:    {:.2}", stats.views_per_visit);
    println!("Bounce Rate:      {:.1}%", stats.bounce_rate);
    println!("Active Now (5m):  {}", stats.active_visitors);
    println!("Cookies Set:      {} (verified zero-cookie)", stats.compliance.cookies_set);
    println!("Raw IPs Stored:   {}", stats.compliance.raw_ips_stored);
    println!("------------------------------------------------------------");
    if !stats.top_pages.is_empty() {
        println!("{:<34} {:>9} {:>10} {:>8}", "Top Pages", "Visitors", "Pageviews", "Bounce");
        for p in stats.top_pages.iter().take(8) {
            println!(
                "{:<34} {:>9} {:>10} {:>7.1}%",
                truncate_label(&p.path, 34),
                p.visitors,
                p.views,
                p.bounce_rate
            );
        }
        println!("------------------------------------------------------------");
    }
    if !stats.top_referrers.is_empty() {
        println!("{:<34} {:>9} {:>10}", "Top Referrers", "Visitors", "Share");
        for r in stats.top_referrers.iter().take(6) {
            println!(
                "{:<34} {:>9} {:>9.1}%",
                truncate_label(&r.name, 34),
                r.visitors,
                r.share
            );
        }
    }
    Ok(())
}

fn run_export_clickhouse(args: ExportClickhouseArgs) -> Result<(), String> {
    let store = ColumnarStore::open(&args.data_dir)
        .map_err(|e| format!("failed to open columnar store: {e}"))?;
    let events = store.export_events(args.site.as_deref(), None);
    let sql = export_clickhouse_sql(&events);
    fs::write(&args.out, sql)
        .map_err(|e| format!("failed to write {}: {e}", args.out.display()))?;
    println!(
        "Exported ClickHouse MergeTree DDL + {} JSONEachRow events to {}",
        events.len(),
        args.out.display()
    );
    Ok(())
}

fn run_validate_plugins(args: ValidatePluginsArgs) -> Result<(), String> {
    match validate_directory(&args.dir) {
        Ok(manifests) => {
            if manifests.is_empty() {
                return Err(format!("no plugin JSON manifests found in {}", args.dir.display()));
            }
            for m in &manifests {
                println!("PASS  {:<28} v{:<7} ({:?})", m.id, m.version, m.kind);
            }
            println!("\nValidated {}/{} plugin manifests cleanly.", manifests.len(), manifests.len());
            Ok(())
        }
        Err(errs) => {
            for e in &errs {
                eprintln!("FAIL  {e}");
            }
            Err(format!("{} plugin validation error(s)", errs.len()))
        }
    }
}

fn print_version() {
    println!("ghostmetrics {VERSION}");
    println!("arch:          {}", std::env::consts::ARCH);
    println!("os:            {}", std::env::consts::OS);
    println!("tracker_bytes: {} bytes raw (< 900 B)", TRACKER_JS.len());
    println!("cookies_set:   0");
}

fn truncate_label(s: &str, max_len: usize) -> String {
    if s.chars().count() <= max_len {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max_len.saturating_sub(3)).collect();
        out.push_str("...");
        out
    }
}
