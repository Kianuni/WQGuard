/**
 * WQGuard Brotli Response Guard (CVE-2026-111497 / HTTP2Shell Mitigation)
 * Compatible with: Surge, Shadowrocket, Loon, Quantumult X, and Stash.
 *
 * Inspects ONLY HTTP response headers (requires-body = false / 0) so neither WebKit/CFNetwork
 * nor the proxy client itself ever decompresses an unsolicited `Content-Encoding: br` stream.
 */
(function () {
  if (typeof $done !== "function") {
    return;
  }

  function safeCoerceHeaderValue(val, depth) {
    if (val === undefined || val === null) {
      return "";
    }
    var t = typeof val;
    if (t === "string" || t === "number" || t === "boolean") {
      return String(val);
    }
    if (Array.isArray(val)) {
      if (depth > 4) {
        return "";
      }
      var parts = [];
      for (var j = 0; j < val.length; j++) {
        var coerced = safeCoerceHeaderValue(val[j], depth + 1);
        if (coerced) {
          parts.push(coerced);
        }
      }
      return parts.join(", ");
    }
    try {
      return String(val);
    } catch (_e) {
      return "";
    }
  }

  var rawResp = typeof $response !== "undefined" ? $response : null;
  var headers = (rawResp && typeof rawResp.headers === "object" && rawResp.headers !== null)
    ? rawResp.headers
    : {};
  var encValues = [];
  var keys = Object.keys(headers);
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    var lk = String(k).trim().toLowerCase();
    if (lk === "content-encoding" || lk === "transfer-encoding") {
      var coercedVal = safeCoerceHeaderValue(headers[k], 0);
      if (coercedVal) {
        encValues.push(coercedVal);
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
