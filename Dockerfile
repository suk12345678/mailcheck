# Stage 1: Build binary using official Rust image
FROM rust:1-bookworm AS builder
WORKDIR /usr/src/mailcheck

# Copy manifests to pre-cache dependencies
COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && echo "pub fn lib() {}" > src/lib.rs && echo "fn main() {}" > src/main.rs && cargo build --release --no-default-features --bin mailcheck && rm -rf src

# Copy real source code
COPY src ./src
RUN touch src/main.rs && cargo build --release --no-default-features --bin mailcheck

# Stage 2: Runtime image using Debian slim (lightweight, secure)
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /usr/src/mailcheck/target/release/mailcheck /app/mailcheck
COPY config.toml /app/config.toml

# Default run: scan unread messages and move detected spam to Junk
ENTRYPOINT ["/app/mailcheck"]
CMD ["scan", "--action", "move-to-junk"]

