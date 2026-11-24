use std::sync::RwLock;

use chrono::{NaiveDate, Utc};
use sha2::{Digest, Sha256};

/// Default sensitive query parameter keys scrubbed even if no PII plugin is loaded.
const DEFAULT_SENSITIVE_PARAMS: &[&str] = &[
    "email",
    "token",
    "api_key",
    "key",
    "password",
    "passwd",
    "secret",
    "auth",
    "ssn",
    "code",
];

/// UTM keys stripped from the normalized path (stored in dedicated OLAP columns instead).
const UTM_KEYS: &[&str] = &[
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
];

/// Known crawler / automated client substrings (case-insensitive).
const BOT_SIGNATURES: &[&str] = &[
    "googlebot",
    "bingbot",
    "ahrefsbot",
    "semrushbot",
    "bytespider",
    "gptbot",
    "claudebot",
    "duckduckbot",
    "yandexbot",
    "baiduspider",
    "slurp",
    "headlesschrome",
    "phantomjs",
    "puppeteer",
    "playwright",
    "curl/",
    "wget/",
    "python-requests",
    "go-http-client",
    "uptime",
    "statuscake",
    "pingdom",
    "datadog",
    "crawler",
    "spider",
];

/// Daily rotating 256-bit in-RAM salt manager.
///
/// The cryptographic salt is generated solely from OS CSPRNG (`getrandom`) and is
/// strictly NEVER persisted to disk. When the UTC calendar day advances, the old
/// salt is overwritten and dropped from memory so visitor hashes cannot be linked
/// across days.
pub struct SaltManager {
    state: RwLock<(NaiveDate, [u8; 32])>,
}

impl Default for SaltManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SaltManager {
    pub fn new() -> Self {
        let today = Utc::now().date_naive();
        let salt = generate_salt_bytes();
        Self {
            state: RwLock::new((today, salt)),
        }
    }

    /// Computes a daily-salted 64-bit visitor hash (returned as both 16-char lowercase
    /// hex and `u64`) using `SHA-256(daily_ram_salt || 0x1f || site_id || 0x1f || client_ip || 0x1f || user_agent)`.
    pub fn visitor_hash(&self, site_id: &str, client_ip: &str, user_agent: &str) -> (String, u64) {
        let today = Utc::now().date_naive();
        let salt = self.salt_for_date(today);
        compute_visitor_hash(&salt, site_id, client_ip, user_agent)
    }

    /// Returns the active 256-bit RAM salt for `date`, rotating if UTC date changed.
    pub fn salt_for_date(&self, date: NaiveDate) -> [u8; 32] {
        {
            let guard = self.state.read().expect("salt lock poisoned");
            if guard.0 == date {
                return guard.1;
            }
        }
        let mut guard = self.state.write().expect("salt lock poisoned");
        if guard.0 != date {
            guard.0 = date;
            guard.1 = generate_salt_bytes();
        }
        guard.1
    }

    pub fn current_utc_day(&self) -> NaiveDate {
        self.state.read().expect("salt lock poisoned").0
    }
}

fn generate_salt_bytes() -> [u8; 32] {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).expect("OS CSPRNG unavailable for RAM salt generation");
    buf
}

pub fn compute_visitor_hash(
    salt: &[u8; 32],
    site_id: &str,
    client_ip: &str,
    user_agent: &str,
) -> (String, u64) {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update([0x1f]);
    hasher.update(site_id.as_bytes());
    hasher.update([0x1f]);
    hasher.update(client_ip.as_bytes());
    hasher.update([0x1f]);
    hasher.update(user_agent.as_bytes());
    let digest = hasher.finalize();

    let mut first8 = [0u8; 8];
    first8.copy_from_slice(&digest[..8]);
    let numeric = u64::from_be_bytes(first8);
    (format!("{numeric:016x}"), numeric)
}

/// Returns `true` if the User-Agent string belongs to a known bot, crawler, or headless probe.
pub fn is_bot(user_agent: &str) -> bool {
    let trimmed = user_agent.trim();
    if trimmed.is_empty() {
        return true;
    }
    let lower = trimmed.to_ascii_lowercase();
    BOT_SIGNATURES.iter().any(|sig| lower.contains(sig))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientInfo {
    pub browser: &'static str,
    pub os: &'static str,
    pub device: &'static str,
}

/// Lightweight zero-regex User-Agent classifier returning broad families only (zero fingerprinting).
pub fn parse_user_agent(ua: &str) -> ClientInfo {
    let lower = ua.to_ascii_lowercase();

    let browser = if lower.contains("edg/") || lower.contains("edge/") {
        "Edge"
    } else if lower.contains("opr/") || lower.contains("opera") {
        "Opera"
    } else if lower.contains("samsungbrowser") {
        "Samsung Internet"
    } else if lower.contains("firefox/") || lower.contains("fxios") {
        "Firefox"
    } else if lower.contains("chrome/") || lower.contains("crios") {
        "Chrome"
    } else if lower.contains("safari/") && !lower.contains("chrome") {
        "Safari"
    } else {
        "Other"
    };

    let os = if lower.contains("iphone") || lower.contains("ipad") || lower.contains("ipod") {
        "iOS"
    } else if lower.contains("android") {
        "Android"
    } else if lower.contains("windows") {
        "Windows"
    } else if lower.contains("mac os x") || lower.contains("macintosh") {
        "macOS"
    } else if lower.contains("cros") {
        "ChromeOS"
    } else if lower.contains("linux") {
        "Linux"
    } else {
        "Other"
    };

    let device = if lower.contains("ipad") || lower.contains("tablet") {
        "Tablet"
    } else if lower.contains("mobile") || lower.contains("iphone") || lower.contains("android") {
        "Mobile"
    } else {
        "Desktop"
    };

    ClientInfo {
        browser,
        os,
        device,
    }
}

/// Scrubs PII from a URL path and query string, returning `(normalized_path, redactions_applied)`.
pub fn scrub_url_path(
    raw_url: &str,
    extra_strip_params: &[String],
    redact_uuids: bool,
    redact_emails: bool,
    numeric_after: &[String],
) -> (String, usize) {
    let mut redactions = 0usize;

    // Strip fragment (#...)
    let no_frag = raw_url.split('#').next().unwrap_or("/");

    // Strip scheme + host if a full URL was submitted
    let path_and_query = if let Some(rest) = no_frag
        .strip_prefix("https://")
        .or_else(|| no_frag.strip_prefix("http://"))
    {
        match rest.find('/') {
            Some(idx) => &rest[idx..],
            None => "/",
        }
    } else {
        no_frag
    };

    let (raw_path, raw_query) = match path_and_query.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path_and_query, None),
    };

    // Normalize path segments and apply segment-level PII redaction
    let mut cleaned_segments: Vec<String> = Vec::new();
    let mut prev_segment_lower = String::new();

    for seg in raw_path.split('/') {
        if seg.is_empty() {
            continue;
        }
        let is_uuid = redact_uuids && looks_like_uuid(seg);
        let is_email = redact_emails && looks_like_email(seg);
        let is_sensitive_id = !prev_segment_lower.is_empty()
            && numeric_after
                .iter()
                .any(|prefix| prefix.eq_ignore_ascii_case(&prev_segment_lower))
            && seg.len() >= 3
            && seg.chars().all(|c| c.is_ascii_digit());

        if is_uuid || is_email || is_sensitive_id {
            cleaned_segments.push("[redacted]".to_string());
            redactions += 1;
            prev_segment_lower.clear();
        } else {
            let safe_seg: String = seg.chars().take(128).collect();
            prev_segment_lower = safe_seg.to_ascii_lowercase();
            cleaned_segments.push(safe_seg);
        }
    }

    let normalized_path = if cleaned_segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", cleaned_segments.join("/"))
    };

    // Scrub query parameters
    let mut kept_params: Vec<&str> = Vec::new();
    if let Some(q) = raw_query {
        for pair in q.split('&') {
            if pair.is_empty() {
                continue;
            }
            let key = pair.split('=').next().unwrap_or("").to_ascii_lowercase();
            let val = pair.split_once('=').map(|(_, v)| v).unwrap_or("");

            if UTM_KEYS.iter().any(|u| *u == key) {
                continue;
            }

            let is_sensitive_key = DEFAULT_SENSITIVE_PARAMS.iter().any(|k| *k == key)
                || extra_strip_params
                    .iter()
                    .any(|k| k.eq_ignore_ascii_case(&key));
            let val_has_pii = redact_emails && looks_like_email(val);

            if is_sensitive_key || val_has_pii {
                redactions += 1;
                continue;
            }

            kept_params.push(pair);
        }
    }

    let final_path = if kept_params.is_empty() {
        normalized_path
    } else {
        format!("{normalized_path}?{}", kept_params.join("&"))
    };

    (final_path.chars().take(512).collect(), redactions)
}

/// Extracts clean referrer domain without scheme, port, path, or `www.` prefix.
/// Returns `"Direct"` for empty, malformed, or self-referring URLs.
pub fn extract_referrer_host(raw_ref: &str, site_domain: &str) -> String {
    let trimmed = raw_ref.trim();
    if trimmed.is_empty() {
        return "Direct".to_string();
    }

    let without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);

    let host_port = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .trim();

    let host = host_port
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();

    let clean = host.strip_prefix("www.").unwrap_or(&host).to_string();
    if clean.is_empty() || !clean.contains('.') {
        return "Direct".to_string();
    }

    let site_clean = site_domain
        .trim()
        .to_ascii_lowercase()
        .strip_prefix("www.")
        .unwrap_or(site_domain)
        .to_string();

    if clean == site_clean {
        return "Direct".to_string();
    }

    clean.chars().take(128).collect()
}

/// Normalizes a site domain identifier.
pub fn normalize_site(raw: &str) -> Option<String> {
    let lower = raw.trim().to_ascii_lowercase();
    let cleaned = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))
        .unwrap_or(&lower);

    let host = cleaned
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .trim()
        .to_string();

    if host.is_empty() || host.len() > 120 {
        return None;
    }

    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
    {
        return None;
    }

    Some(host)
}

/// Neutralizes CSV formula injection (`=`, `+`, `-`, `@`, `\t`, `\r`) and escapes RFC-4180 quotes.
pub fn sanitize_csv_cell(value: &str) -> String {
    let clean = value.replace(['\r', '\n'], " ");
    let neutralized = match clean.chars().next() {
        Some('=' | '+' | '-' | '@' | '\t') => format!("'{clean}"),
        _ => clean,
    };
    if neutralized.contains([',', '"', ' ']) || neutralized.starts_with('\'') {
        format!("\"{}\"", neutralized.replace('"', "\"\""))
    } else {
        neutralized
    }
}

fn looks_like_uuid(seg: &str) -> bool {
    if seg.len() != 36 {
        return false;
    }
    let bytes = seg.as_bytes();
    for (idx, b) in bytes.iter().enumerate() {
        if matches!(idx, 8 | 13 | 18 | 23) {
            if *b != b'-' {
                return false;
            }
        } else if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

fn looks_like_email(seg: &str) -> bool {
    let decoded = seg.replace("%40", "@");
    if let Some((local, domain)) = decoded.split_once('@') {
        !local.is_empty() && domain.contains('.') && !domain.ends_with('.')
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daily_salt_rotates_and_produces_unlinkable_hashes() {
        let mgr = SaltManager::new();
        let d1 = NaiveDate::from_ymd_opt(2026, 5, 1).unwrap();
        let d2 = NaiveDate::from_ymd_opt(2026, 5, 2).unwrap();

        let s1 = mgr.salt_for_date(d1);
        let s1_repeat = mgr.salt_for_date(d1);
        assert_eq!(s1, s1_repeat, "Salt must stay stable within same UTC day");

        let (h1a, n1a) = compute_visitor_hash(&s1, "demo.local", "203.0.113.10", "Mozilla/5.0");
        let (h1b, n1b) = compute_visitor_hash(&s1, "demo.local", "203.0.113.10", "Mozilla/5.0");
        assert_eq!(h1a, h1b);
        assert_eq!(n1a, n1b);
        assert_eq!(h1a.len(), 16);

        let s2 = mgr.salt_for_date(d2);
        assert_ne!(s1, s2, "Salt must rotate on UTC day rollover");
        let (h2, _) = compute_visitor_hash(&s2, "demo.local", "203.0.113.10", "Mozilla/5.0");
        assert_ne!(h1a, h2, "Hashes across UTC days must be unlinkable");
    }

    #[test]
    fn bot_classifier_filters_crawlers_and_allows_browsers() {
        assert!(is_bot(""));
        assert!(is_bot("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"));
        assert!(is_bot("GPTBot/1.0"));
        assert!(is_bot("HeadlessChrome/124.0"));
        assert!(is_bot("curl/8.4.0"));
        assert!(is_bot("python-requests/2.31.0"));
        assert!(!is_bot(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15"
        ));
    }

    #[test]
    fn url_scrubber_strips_pii_params_uuids_and_emails() {
        let extra = vec!["fbclid".to_string()];
        let num_after = vec!["users".to_string(), "orders".to_string()];

        let (clean, count) = scrub_url_path(
            "/users/982341/550e8400-e29b-41d4-a716-446655440000/profile?email=alice@example.com&token=secret123&fbclid=abc&tab=billing&utm_source=hn",
            &extra,
            true,
            true,
            &num_after,
        );
        assert_eq!(clean, "/users/[redacted]/[redacted]/profile?tab=billing");
        assert_eq!(count, 5);
    }

    #[test]
    fn referrer_extractor_normalizes_and_drops_self_referrals() {
        assert_eq!(
            extract_referrer_host("https://www.news.ycombinator.com/item?id=123", "demo.local"),
            "news.ycombinator.com"
        );
        assert_eq!(
            extract_referrer_host("https://demo.local/pricing", "demo.local"),
            "Direct"
        );
        assert_eq!(extract_referrer_host("", "demo.local"), "Direct");
    }

    #[test]
    fn user_agent_parser_identifies_families() {
        let info = parse_user_agent(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
        );
        assert_eq!(info.browser, "Edge");
        assert_eq!(info.os, "Windows");
        assert_eq!(info.device, "Desktop");

        let ios = parse_user_agent(
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
        );
        assert_eq!(ios.browser, "Safari");
        assert_eq!(ios.os, "iOS");
        assert_eq!(ios.device, "Mobile");
    }

    #[test]
    fn csv_sanitizer_neutralizes_formula_injection() {
        assert_eq!(sanitize_csv_cell("=CMD|' /C calc'!A0"), "\"'=CMD|' /C calc'!A0\"");
        assert_eq!(sanitize_csv_cell("+1+1"), "\"'+1+1\"");
        assert_eq!(sanitize_csv_cell("/pricing"), "/pricing");
    }
}
