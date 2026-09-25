(() => {
  const base = (window.SENTINEL_API_URL || "http://127.0.0.1:8000").replace(/\/$/, "");
  async function request(path, options = {}) {
    let response;
    try { response = await fetch(base + path, { ...options, credentials: "include", headers: { "Content-Type": "application/json", ...(options.headers || {}) } }); }
    catch { throw new Error("SentinelAPI scanner is unavailable. Start the local backend and retry."); }
    let data; try { data = await response.json(); } catch { throw new Error("The scanner returned an invalid response."); }
    if (!response.ok) throw new Error(data.detail || `Scanner request failed (${response.status}).`);
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