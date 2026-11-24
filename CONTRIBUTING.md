# Contributing to GhostMetrics

Thank you for helping keep web analytics fast, privacy-first, and $0 forever. Contributions are welcome across three core areas:

1. **Community JSON Plugins (`plugins/`):** Referrer spam lists, PII redaction presets, conversion funnels, traffic spike rules, and Markdown digest templates.
2. **Rust OLAP & Storage (`src/storage/`):** Columnar compression, SIMD-friendly vector scans, ClickHouse query templates, and ingestion throughput improvements.
3. **Minimalist Alpine.js Dashboard (`web/`):** Clean visual refinements that uphold zero external CDNs, zero cookies, and strict Light/Dark contrast.

---

## Quick Plugin Contribution (25-Line JSON Template)

You do not need to write Rust to ship a GhostMetrics plugin. Create a file in `plugins/<your-plugin-id>.json` matching `plugins/schema.json`:

```json
{
  "id": "docs-onboarding-funnel",
  "name": "Docs Onboarding Funnel",
  "version": "1.0.0",
  "kind": "funnel",
  "description": "Measures visitor progression from homepage through docs quickstart to CLI copy.",
  "author": "Your Name",
  "enabled": true,
  "config": {
    "steps": [
      {
        "label": "Homepage",
        "event_name": "pageview",
        "path_prefix": "/"
      },
      {
        "label": "Quickstart Docs",
        "event_name": "pageview",
        "path_prefix": "/docs/getting-started"
      },
      {
        "label": "CLI Install Copied",
        "event_name": "cli_install_copied"
      }
    ]
  }
}
```

Supported plugin `kind` values:
- `referrer_filter` (`config.blocked_domains`: array of domain strings)
- `pii_redactor` (`config.strip_query_params`, `redact_uuid_segments`, `redact_email_segments`, `redact_numeric_segments_after`)
- `funnel` (`config.steps`: at least 2 steps with `label`, `event_name`, optional `path_prefix`)
- `spike_alert` (`config.threshold_active_5m >= 1`, `config.window_minutes` in `1..60`)
- `digest_template` (`config.title`, `config.include_sections`, `config.footer_note`)

---

## Non-Negotiable Engineering Standards

Before opening a pull request, verify your change upholds every architectural invariant:

1. **Zero Cookies & Zero Raw IPs:** No route may ever set a `Set-Cookie` header, and no code path may write raw visitor IP addresses to disk or exports.
2. **Tracker Size Budget (`< 900 B`):** `web/ghost.js` must remain strictly under 900 bytes raw with zero `document.cookie` or `localStorage` usage.
3. **Zero External Dependencies at Runtime:** Keep `Cargo.toml` free of C/OpenSSL native build scripts (`openssl-sys`, `ring`) so single-binary cross-compilation remains fast and reliable. Keep the dashboard free of external CDN calls.
4. **Minimalist Design System:** Crisp Light and Dark CSS variables, 1px hairline borders, restrained neutral surfaces, tabular monospace metrics, zero emojis, and zero neon gradients.

---

## Local Verification Checklist

Run all checks locally before submitting a pull request:

```bash
# 1. Validate all community JSON plugins (Node validator + Rust CLI validator)
node scripts/validate-plugins.mjs plugins
cargo run -- validate-plugins --dir ./plugins

# 2. Run all Rust unit tests and Axum integration tests
cargo test -- --nocapture

# 3. Run strict Clippy lint checks (zero warnings allowed)
cargo clippy --all-targets -- -D warnings

# 4. Verify optimized release binary compiles cleanly
cargo build --release
```

---

## Pull Request Process

1. Fork the repository and create a focused feature branch (`feat/...` or `fix/...`).
2. Add unit or Axum `oneshot` integration tests covering any new Rust behavior.
3. Run the verification checklist above and ensure 100% pass rate.
4. Open a pull request with a concise summary of the change and benchmark/test output.
