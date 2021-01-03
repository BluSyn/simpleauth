### BUILDING APP ###
# FROM rust:1.46 as build
# RUN cargo build --release

### RUNNING APP ###
FROM alpine:latest
ENTRYPOINT ["/app/simpleauth"]
EXPOSE 3141

COPY target/release/simpleauth /app/simpleauth
