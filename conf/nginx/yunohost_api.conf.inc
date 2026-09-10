location /yunohost/api/ {
    proxy_read_timeout 3600s;
    proxy_pass http://127.0.0.1:6787/;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;

    {% if webadmin_allowlist_enabled == "True" %}
    {% for ip in webadmin_allowlist.split(',') %}
    allow {{ ip }};
    {% endfor %}
    deny all;
    {% endif %}

    # Custom 502 error page
    error_page 502 /yunohost/api/error/502;
}

# Yunohost admin output complete 502 error page, so use only plain text.
location = /yunohost/api/error/502 {
    return 502 '502 - Bad Gateway';
    add_header Content-Type text/plain;
    internal;
}

location /yunohost/portalapi/ {

    proxy_read_timeout 30s;
    proxy_pass http://127.0.0.1:6788/;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;

    # Custom 502 error page
    error_page 502 /yunohost/portalapi/error/502;
}

# Internal authentication subrequest for the NostrHost compatibility bridge.
# Keep this endpoint unreachable from the public network and bypass legacy
# SSOwat for this one request: the portal API performs the canonical session
# cookie, host, allow-list, and session-file checks.
location = /yunohost/portalapi/nostr/auth-request {
    internal;
    access_by_lua off;
    proxy_pass http://127.0.0.1:6788/nostr/auth-request;
    proxy_set_header Host $host;
    proxy_set_header X-Original-URI $request_uri;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
}

# Public OIDC compatibility endpoints.  Authentication is enforced by the
# authorization endpoint itself through the portal session; discovery, JWKS,
# token exchange, and userinfo must not be intercepted by legacy SSOwat.
location = /.well-known/openid-configuration {
    proxy_pass http://127.0.0.1:6788;
    proxy_read_timeout 30s;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
}

location ^~ /oidc/ {
    proxy_pass http://127.0.0.1:6788;
    proxy_read_timeout 30s;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
}

# OAuth token requests are form-encoded by specification and would otherwise
# be rejected by Moulinette's browser-oriented CSRF filter.  The token route
# still requires a one-time code, exact redirect URI, and client secret.
location = /oidc/token {
    proxy_pass http://127.0.0.1:6788;
    proxy_read_timeout 30s;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Requested-With "NostrHost-OIDC";
}


# Yunohost admin output complete 502 error page, so use only plain text.
location = /yunohost/portalapi/error/502 {
    return 502 '502 - Bad Gateway';
    add_header Content-Type text/plain;
    internal;
}
