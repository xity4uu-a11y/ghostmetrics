# syntax=docker/dockerfile:1

FROM rust:1.85-slim-bookworm AS builder
WORKDIR /app

COPY Cargo.toml ./
COPY src ./src
COPY web ./web
COPY plugins ./plugins
COPY schema ./schema

RUN cargo build --release --locked 2>/dev/null || cargo build --release

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 -m ghostmetrics \
    && mkdir -p /data /etc/ghostmetrics/plugins \
    && chown -R ghostmetrics:ghostmetrics /data /etc/ghostmetrics

COPY --from=builder /app/target/release/ghostmetrics /usr/local/bin/ghostmetrics
COPY --from=builder /app/plugins /etc/ghostmetrics/plugins

USER ghostmetrics
WORKDIR /data

ENV GHOSTMETRICS_ADDR=0.0.0.0:8080 \
    GHOSTMETRICS_DATA_DIR=/data \
    GHOSTMETRICS_PLUGINS_DIR=/etc/ghostmetrics/plugins

EXPOSE 8080
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/ghostmetrics"]
CMD ["serve"]
