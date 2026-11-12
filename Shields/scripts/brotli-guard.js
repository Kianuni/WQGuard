/**
 * WQGuard Brotli Response Guard (CVE-2026-111497 / HTTP2Shell Mitigation)
 * Compatible with: Surge, Shadowrocket, Loon, Quantumult X, and Stash.
 *
 * Inspects ONLY HTTP response headers (requires-body = false / 0) so neither WebKit/CFNetwork
 * nor the proxy client itself ever decompresses an unsolicited `Content-Encoding: br` stream.
 */
(function () {
  var headers = ($response && $response.headers) || {};
  var rawCE = headers["Content-Encoding"] || headers["content-encoding"] || "";
  var hasBrotli = /(^|[,\s])br($|[,\s;])/i.test(String(rawCE));

  if (!hasBrotli) {
    $done({});
    return;
  }

  var msg = "WQGuard Brotli Shield: Blocked unsolicited Brotli response stream to mitigate CVE-2026-111497.";

  // Quantumult X (`script-response-header` environment)
  if (typeof $task !== "undefined") {
    $done({
      status: "HTTP/1.1 403 Forbidden",
      headers: {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Length": "0",
        "Connection": "close",
        "X-WQGuard-Shield": "Blocked-Unsolicited-Brotli"
      }
    });
    return;
  }

  // Surge / Shadowrocket / Loon / Stash environment
  $done({
    response: {
      status: 403,
      headers: {
        "Content-Type": "text/plain; charset=utf-8",
        "X-WQGuard-Shield": "Blocked-Unsolicited-Brotli"
      },
      body: msg
    }
  });
})();
