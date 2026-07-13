# 1. Build Stage
FROM rust:1.88-slim-bookworm AS builder

WORKDIR /usr/src/aegis-llm
COPY . .
RUN cargo build --release

# 2. Run Stage
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /usr/src/aegis-llm/target/release/aegis-llm /usr/local/bin/aegis-llm

EXPOSE 8080
ENTRYPOINT ["aegis-llm"]
