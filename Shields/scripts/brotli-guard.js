/**
 * WQGuard Brotli Response Guard (CVE-2026-111497 / HTTP2Shell Mitigation)
 * Compatible with: Surge, Shadowrocket, Loon, Quantumult X, and Stash.
 *
 * Inspects ONLY HTTP response headers (requires-body = false / 0) so neither WebKit/CFNetwork
 * nor the proxy client itself ever decompresses an unsolicited `Content-Encoding: br` stream.
 */
(function () {
  var headers = ($response && $response.headers) || {};
  var encValues = [];
  var keys = Object.keys(headers);
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    var lk = String(k).trim().toLowerCase();
    if (lk === "content-encoding" || lk === "transfer-encoding") {
      var v = headers[k];
      if (Array.isArray(v)) {
        encValues.push(v.join(", "));
      } else if (v !== undefined && v !== null) {
        encValues.push(String(v));
      }
    }
  }
  var rawEnc = encValues.join(", ");
  var hasBrotli = /(^|[^A-Za-z0-9_.-])((?:x-)?(?:br|brotli|dcb|sbr))($|[^A-Za-z0-9_.-])/i.test(rawEnc);

  if (!hasBrotli) {
    $done({});
    return;
  }

  // Quantumult X (`script-response-header` environment exposes `$task` / `$prefs` without Surge/Loon `$httpClient` / `$loon`)
  if ((typeof $task !== "undefined" || typeof $prefs !== "undefined") && typeof $loon === "undefined" && typeof $httpClient === "undefined") {
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

  // Surge / Shadowrocket / Loon / Stash `http-response` (requires-body = false) environment:
  // Top-level `status` + `headers` without `body` or nested `response` wrapper is mandatory.
  $done({
    status: 403,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Content-Length": "0",
      "Connection": "close",
      "X-WQGuard-Shield": "Blocked-Unsolicited-Brotli"
    }
  });
})();
