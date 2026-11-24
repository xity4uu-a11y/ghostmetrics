#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";

const dir = process.argv[2] ? path.resolve(process.argv[2]) : path.resolve("plugins");
const VALID_KINDS = new Set([
  "referrer_filter",
  "pii_redactor",
  "funnel",
  "spike_alert",
  "digest_template",
]);
const ID_RE = /^[a-z0-9][a-z0-9-]{2,63}$/;
const SEMVER_RE = /^\d+\.\d+\.\d+$/;
const ALLOWED_TOP_KEYS = new Set([
  "id",
  "name",
  "version",
  "kind",
  "description",
  "author",
  "enabled",
  "config",
]);

function validatePlugin(filePath, raw) {
  const errors = [];
  let data;
  try {
    data = JSON.parse(raw);
  } catch (err) {
    return [`Invalid JSON: ${err.message}`];
  }

  if (!data || typeof data !== "object" || Array.isArray(data)) {
    return ["Root manifest must be a JSON object."];
  }

  for (const key of ALLOWED_TOP_KEYS) {
    if (!(key in data)) {
      errors.push(`Missing required field '${key}'.`);
    }
  }
  for (const key of Object.keys(data)) {
    if (!ALLOWED_TOP_KEYS.has(key)) {
      errors.push(`Unexpected top-level field '${key}'.`);
    }
  }

  if (typeof data.id !== "string" || !ID_RE.test(data.id)) {
    errors.push("Field 'id' must match ^[a-z0-9][a-z0-9-]{2,63}$.");
  }
  if (typeof data.name !== "string" || data.name.length < 3 || data.name.length > 80) {
    errors.push("Field 'name' must be a string between 3 and 80 characters.");
  }
  if (typeof data.version !== "string" || !SEMVER_RE.test(data.version)) {
    errors.push("Field 'version' must be valid semver (X.Y.Z).");
  }
  if (typeof data.kind !== "string" || !VALID_KINDS.has(data.kind)) {
    errors.push(`Field 'kind' must be one of: ${Array.from(VALID_KINDS).join(", ")}.`);
  }
  if (typeof data.description !== "string" || data.description.length < 10 || data.description.length > 240) {
    errors.push("Field 'description' must be 10..240 characters.");
  }
  if (typeof data.author !== "string" || data.author.length < 2 || data.author.length > 80) {
    errors.push("Field 'author' must be 2..80 characters.");
  }
  if (typeof data.enabled !== "boolean") {
    errors.push("Field 'enabled' must be a boolean.");
  }
  if (!data.config || typeof data.config !== "object" || Array.isArray(data.config)) {
    errors.push("Field 'config' must be an object.");
    return errors;
  }

  // Kind-specific config checks
  const cfg = data.config;
  if (data.kind === "referrer_filter") {
    if (!Array.isArray(cfg.blocked_domains) || cfg.blocked_domains.length === 0) {
      errors.push("referrer_filter requires non-empty config.blocked_domains array.");
    } else if (!cfg.blocked_domains.every((d) => typeof d === "string" && d.includes("."))) {
      errors.push("referrer_filter config.blocked_domains entries must be valid domain strings.");
    }
  } else if (data.kind === "pii_redactor") {
    if (!Array.isArray(cfg.strip_query_params) || cfg.strip_query_params.length === 0) {
      errors.push("pii_redactor requires non-empty config.strip_query_params array.");
    }
  } else if (data.kind === "funnel") {
    if (!Array.isArray(cfg.steps) || cfg.steps.length < 2) {
      errors.push("funnel requires config.steps with at least 2 steps.");
    } else {
      cfg.steps.forEach((step, idx) => {
        if (!step || typeof step.label !== "string" || typeof step.event_name !== "string") {
          errors.push(`funnel config.steps[${idx}] requires 'label' and 'event_name'.`);
        }
      });
    }
  } else if (data.kind === "spike_alert") {
    if (typeof cfg.threshold_active_5m !== "number" || cfg.threshold_active_5m < 1) {
      errors.push("spike_alert requires config.threshold_active_5m >= 1.");
    }
    if (typeof cfg.window_minutes !== "number" || cfg.window_minutes < 1 || cfg.window_minutes > 60) {
      errors.push("spike_alert requires config.window_minutes between 1 and 60.");
    }
  } else if (data.kind === "digest_template") {
    if (typeof cfg.title !== "string" || cfg.title.length < 3) {
      errors.push("digest_template requires config.title.");
    }
    if (!Array.isArray(cfg.include_sections) || cfg.include_sections.length === 0) {
      errors.push("digest_template requires non-empty config.include_sections.");
    }
  }

  const expectedBase = `${data.id}.json`;
  if (typeof data.id === "string" && path.basename(filePath) !== expectedBase) {
    errors.push(`Filename '${path.basename(filePath)}' must match id '${expectedBase}'.`);
  }

  return errors;
}

if (!fs.existsSync(dir)) {
  console.error(`Plugins directory not found: ${dir}`);
  process.exit(1);
}

const files = fs
  .readdirSync(dir)
  .filter((f) => f.endsWith(".json") && f !== "schema.json")
  .sort();

if (files.length === 0) {
  console.error("No plugin JSON manifests found.");
  process.exit(1);
}

let passed = 0;
let failed = 0;
const seenIds = new Set();

for (const file of files) {
  const fullPath = path.join(dir, file);
  const raw = fs.readFileSync(fullPath, "utf8");
  const errors = validatePlugin(fullPath, raw);
  try {
    const parsed = JSON.parse(raw);
    if (parsed.id && seenIds.has(parsed.id)) {
      errors.push(`Duplicate plugin id '${parsed.id}'.`);
    }
    if (parsed.id) seenIds.add(parsed.id);
  } catch (_) {}

  if (errors.length === 0) {
    passed += 1;
    console.log(`PASS  ${file}`);
  } else {
    failed += 1;
    console.error(`FAIL  ${file}`);
    for (const err of errors) {
      console.error(`      - ${err}`);
    }
  }
}

console.log(`\nPlugin validation summary: ${passed}/${files.length} PASS, ${failed} FAIL`);
if (failed > 0) process.exit(1);
