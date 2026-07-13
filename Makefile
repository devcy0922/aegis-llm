.PHONY: build test check run benchmark help

help:
	@echo "AegisLLM Makefile Commands:"
	@echo "  build     - Build the Rust release binary"
	@echo "  test      - Run cargo tests"
	@echo "  check     - Check codebase syntax and types using cargo check"
	@echo "  run       - Run the gateway in release mode with default config"
	@echo "  benchmark - Execute a local performance benchmark using wrk"

build:
	cargo build --release

test:
	cargo test --workspace

check:
	cargo check

run:
	cargo run --release -- --config configs/gateway.toml

benchmark:
	@echo "Starting AegisLLM Benchmark..."
	@if command -v wrk > /dev/null; then \
		wrk -t4 -c50 -d10s http://localhost:8080/health; \
	else \
		echo "Error: 'wrk' load testing tool is not installed."; \
		exit 1; \
	fi
