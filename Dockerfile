### BUILDING APP ###
# FROM rust:1.46 as build
# RUN cargo build --release

### RUNNING APP ###
FROM alpine:latest
ENTRYPOINT ["/app/entrypoint.sh"]
EXPOSE 3141

COPY entrypoint.sh /app/entrypoint.sh
COPY target/release/simpleauth /app/simpleauth
