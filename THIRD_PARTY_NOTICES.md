# Third-Party Notices

GhostMetrics embeds the following self-hosted open-source component so the compiled single binary has zero external CDN dependencies:

## Alpine.js (v3.14.8)

- **File:** `web/alpine.min.js`
- **Source:** https://github.com/alpinejs/alpine
- **License:** MIT License
- **Copyright:** Copyright (c) 2019-2024 Caleb Porzio and contributors

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.

## Rust Crates

GhostMetrics statically links permissive open-source Rust crates listed in `Cargo.toml` (`axum`, `tokio`, `tower-http`, `serde`, `serde_json`, `sha2`, `chrono`, `clap`, `getrandom`, `tokio-stream`, `futures-util`), all licensed under MIT and/or Apache-2.0.
