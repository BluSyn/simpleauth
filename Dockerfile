### BUILDING APP ###
FROM rust:latest as build

# Minimal work env
WORKDIR /app
COPY . .

# Build
RUN cargo build --release

### RUNNING APP ###
FROM debian:buster-slim
ENTRYPOINT ["/app/entrypoint.sh"]
EXPOSE 3141

RUN apt-get update && apt-get install -y \
    --no-install-recommends \
    openssl \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /app/entrypoint.sh
COPY templates /app/templates
COPY --from=build /app/target/release/simpleauth /app/simpleauth
