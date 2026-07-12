# AegisLLM

AegisLLM is a high-performance, security-first API gateway and proxy for LLM endpoints, built in Rust with Axum. It intercepts chat completion requests to enforce security policies, detect secrets, mask PII, and record structured audit logs.

## Features

- **Prompt Security**: Filters inputs against prompt injection payloads.
- **Data Loss Prevention (DLP)**: Scans and redacts PII (email, resident registration numbers) and API keys.
- **3-Tier Authentication**: Fallback static key configuration via environment variables for independent deployments.
- **Observability**: Emits structured JSONL audit logs and Prometheus metrics.

## API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/v1/chat/completions` | `POST` | Intercepts, filters, and proxies chat completion requests. |
| `/v1/models` | `GET` | Lists authorized models. |
| `/health` | `GET` | Returns service status. |
| `/metrics` | `GET` | Exposes Prometheus telemetry. |

## Build and Run

### Running locally
```bash
cargo run --release -- --config configs/gateway.toml
```

### Running with Docker
```bash
docker build -t aegis-llm .
docker run -p 8080:8080 -v ./configs/gateway.toml:/app/configs/gateway.toml aegis-llm
```

## Configuration

Settings are declared in `configs/gateway.toml` or overridden via environment variables:
- `AEGIS_CONFIG`: Path to target TOML configuration.
- `AEGIS_API_KEYS`: Comma-separated authentication keys (Format: `key:project:role[:rpm]`).
