# Avoid the nginx path/alias traversal weakness ( #1037 )
rewrite ^/yunohost/sso$ /yunohost/sso/ permanent;

location /yunohost/sso/ {
    alias /usr/share/yunohost/portal/;
    default_type text/html;
    index index.html;
    try_files $uri $uri/ /yunohost/sso/index.html;

    location = /yunohost/sso/index.html {
        etag off;
        expires off;
        more_set_headers "Cache-Control: no-store, no-cache, must-revalidate";
    }

    location /yunohost/sso/applogos/ {
        alias /usr/share/yunohost/applogos/;
    }

    location = /yunohost/sso/customassets/custom.css {
        alias /usr/share/yunohost/portal/customassets/$host.custom.css;
        etag off;
        expires off;
        more_set_headers "Cache-Control: no-store, no-cache, must-revalidate";
    }

    # NIP-46 remote-signer login lets the user paste a bunker:// URI whose
    # relay may be any ws/wss endpoint (the portal connects to it from the
    # browser to perform the NIP-46 handshake), so connect-src must allow
    # websocket destinations in addition to same-origin API calls.
    more_set_headers "Content-Security-Policy: upgrade-insecure-requests; default-src 'self'; connect-src 'self' ws: wss:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; object-src 'none'; img-src 'self' data:;";
}
