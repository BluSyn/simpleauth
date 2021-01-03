### BUILDING APP ###
# FROM rust:1.46 as build
# RUN cargo build --release
FROM rust:1.49-alpine as build

# Build time options to avoid dpkg warnings and help with reproducible builds.
ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8 TZ=UTC TERM=xterm-256color

# Minimal work env
RUN rustup set profile minimal
WORKDIR /app
COPY . .

# Build
RUN cargo build --release

### RUNNING APP ###
FROM alpine:latest
ENTRYPOINT ["/app/entrypoint.sh"]
EXPOSE 3141

RUN apk update && \
	apk add --no-cache openssl curl ca-certificates

COPY entrypoint.sh /app/entrypoint.sh
COPY --from=build app/target/release/simpleauth .
