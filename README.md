simpleauth
==========

`simpleauth` is a middleware for nginx to replace HTTP "Authorization" popups with a pretty HTML form.

Built with `rust` and [Rocket](https://rocket.rs).

This acts as an auth bridge between a web service that requires HTTP Auth, while still allowing standard HTTP Auth requests to passthrough.


## Usage

Ideally used with docker and `nginx` reverse-proxy, such as [nginx-proxy](https://github.com/nginx-proxy/nginx-proxy/).
Update `nginx/auth.conf` with your internal domain for redirect.

Copy `auth.toml` and configure host/login pairs.

Start `simpleauth` service has a separate container. All authenticated requests will ask `simpleauth` for validation before proceeding.

Example with `docker-compose`:

```yaml
version: '2'

services:
  nginx-proxy:
    image: nginxproxy/nginx-proxy
    ports:
      - "80:80"
    volumes:
      - /var/run/docker.sock:/tmp/docker.sock:ro
      - ./config/nginx/auth.conf:/etc/nginx/vhost.d/auth.conf:ro
  auth:
    build: simpleauth
    environment:
      VIRTUAL_HOST: auth.example.domain
      VIRTUAL_PORT: 3141
      ROCKET_SECRET_KEY: "<GENERATE WITH `openssl rand -base64 32`>"
      ROCKET_TEMPLATE_DIR: "templates/"
    volumes:
      - ./secrets/auth.toml:/app/auth.toml

  secret_service:
  // ..
    environment:
      SIMPLE_AUTH: "true"

```

For `nginx-proxy`, a custom `nginx.tmpl` is required, with the addition of:
```conf
        {{ if eq $simple_auth "true" }}
        include /etc/nginx/vhost.d/auth.conf;
        {{ end }}
```

*TODO:* Improve nginx-proxy example, documentation, and create service example.
