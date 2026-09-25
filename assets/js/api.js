(() => {
  const base = (window.SENTINEL_API_URL || "").replace(/\/$/, "");
  async function request(path, options = {}) {
    let response;
    try { response = await fetch(base + path, { ...options, credentials: "include", headers: { "Content-Type": "application/json", ...(options.headers || {}) } }); }
    catch {
      throw new Error(window.SENTINELAPI_IS_HOSTED
        ? "SentinelAPI service is temporarily unavailable. Please try again."
        : "SentinelAPI scanner is unavailable. Start the local backend and retry.");
    }
    const contentType = response.headers.get("content-type") || "";
    let data = null;
    if (contentType.includes("application/json")) {
      try { data = await response.json(); } catch { /* Use a safe status-based message below. */ }
    } else {
      try { await response.text(); } catch { /* The response body is not needed for safe errors. */ }
    }
    if (!response.ok) {
      const detail = response.status < 500 && typeof data?.detail === "string" ? data.detail : null;
      throw new Error(detail || (response.status >= 500
        ? "Scanner service is temporarily unavailable. Please try again."
        : `Scanner request failed (${response.status}).`));
    }
    if (!data || typeof data !== "object") {
      throw new Error("Scanner service returned an unexpected response. Please try again.");
    }
    return data;
  }
  window.SentinelAPI = {
    base,
    health: () => request("/api/health"),
    listScans: () => request("/api/scans"),
    createScan: (data) => request("/api/scans", { method: "POST", body: JSON.stringify(data) }),
    getScan: (id) => request("/api/scans/" + encodeURIComponent(id))
  };
})();