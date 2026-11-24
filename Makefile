.PHONY: dev build test clippy validate-plugins demo docker-build docker-up clean

dev:
	cargo run -- serve --addr 127.0.0.1:8080 --seed-demo

build:
	cargo build --release

test:
	cargo test -- --nocapture

clippy:
	cargo clippy --all-targets -- -D warnings

validate-plugins:
	node scripts/validate-plugins.mjs plugins
	cargo run -- validate-plugins --dir ./plugins

demo:
	cargo run --release -- serve --addr 127.0.0.1:8080 --seed-demo

docker-build:
	docker build -t ghcr.io/xity4uu-a11y/ghostmetrics:latest .

docker-up:
	docker compose --profile clickhouse up -d

clean:
	cargo clean
	rm -rf dist ghostmetrics-data
