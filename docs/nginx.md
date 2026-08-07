# Nginx perimeter limiting

Nginx limiting is an optional outer layer. It reduces obvious floods before they
reach Django, but it neither replaces the Redis risk engine nor proves that an
address belongs to one person.

`limit_req_zone` is valid only in Nginx's `http` context. Install the snippets in
two distinct places:

```nginx
http {
    include /etc/nginx/snippets/http-rate-limits.conf;

    server {
        # TLS, server_name, upstream, and normal host configuration...
        include /etc/nginx/snippets/triadcaptcha-locations.conf;
    }
}
```

- [`infra/nginx/http-rate-limits.conf`](../infra/nginx/http-rate-limits.conf)
  defines shared zones and belongs in `http {}`.
- [`infra/nginx/triadcaptcha-locations.conf`](../infra/nginx/triadcaptcha-locations.conf)
  consumes those zones and belongs in `server {}`. Adapt the upstream and protected
endpoint names.

The challenge location deliberately covers both the canonical trailing-slash URL
and the no-slash form, so a redirect request cannot bypass the perimeter zone.

After editing the host configuration, always run `nginx -t`; only reload after it
reports success (for example `nginx -s reload` or `systemctl reload nginx`). Do not
paste the location snippet alone and treat it as a self-contained server config.

The supplied location snippet overwrites `X-Forwarded-For` with Nginx's
`$remote_addr`; it never appends an untrusted client header. When another proxy/CDN
sits in front of Nginx, first configure Nginx real-IP handling for that proxy's
exact networks so `$remote_addr` is trustworthy, then configure TriadCAPTCHA to
trust only the exact network between Nginx and Django. The Compose
`172.16.0.0/12` value accommodates Docker's dynamically selected private subnet;
do not copy that broad range to a host deployment that has a fixed proxy address.
The reference snippet sets `X-Forwarded-Proto` from its own `$scheme`. If TLS is
terminated at a trusted proxy before this Nginx, restrict direct ingress and adapt
that header to the verified original scheme (often a fixed `https`); never relay an
arbitrary client's `X-Forwarded-Proto`. Align Django's
`SECURE_PROXY_SSL_HEADER`, CSRF origins, and Secure-cookie setting with that edge.

The server-level snippet converts Nginx's own `limit_req` rejection to the stable
JSON `ANTIBOT_RATE_LIMITED` contract with a conservative `Retry-After: 6` (the
slowest configured zone refills at 10 requests/minute). Upstream responses are
not intercepted, so an application's unrelated 429 response remains its own.
