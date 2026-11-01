import http.client
import ssl
from urllib.parse import urlparse

USER_AGENT = "Mozilla/5.0 (compatible; DomainMonitor/1.0)"


def _try(host, port, use_ssl, timeout):
    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False          # fake sites often have bad certificates,
            ctx.verify_mode = ssl.CERT_NONE     # we only want to know if a server answers
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("GET", "/", headers={"User-Agent": USER_AGENT, "Connection": "close"})
        resp = conn.getresponse()               # reads status line + headers only
        info = {"status": resp.status,
                "server": resp.getheader("Server") or "",
                "location": resp.getheader("Location") or ""}
        conn.close()                            # body is never downloaded
        return info
    except (OSError, http.client.HTTPException):
        return None                             # timeout, refused, SSL error, bad response...


def check_web(host, ports=((443, True), (80, False)), timeout=4):
    """
    Returns a dict:
      text    : short label for the report, e.g. 'LIVE (200)', 'REDIRECT (301)', 'NO WEB'
      status  : HTTP status code or None
      server  : Server header (e.g. 'cloudflare', 'nginx')
      redirect_to : host the page redirects to (if any)
    """
    for port, use_ssl in ports:
        info = _try(host, port, use_ssl, timeout)
        if info:
            status = info["status"]
            if 200 <= status < 300:
                label = "LIVE"
            elif 300 <= status < 400:
                label = "REDIRECT"
            else:
                label = "HTTP"
            target = urlparse(info["location"]).netloc if info["location"] else ""
            return {"text": f"{label} ({status})", "status": status,
                    "server": info["server"], "redirect_to": target}
    return {"text": "NO WEB", "status": None, "server": "", "redirect_to": ""}


