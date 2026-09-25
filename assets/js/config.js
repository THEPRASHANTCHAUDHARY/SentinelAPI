(() => {
  const hostname = location.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  const loopbackHost = hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1";
  const fileFrontend = location.protocol === "file:";
  const localFrontend = fileFrontend || location.port === "5500";
  const defaultApi = localFrontend
    ? "http://127.0.0.1:8000"
    : loopbackHost ? location.origin : "";
  window.SENTINEL_API_URL = window.SENTINEL_API_URL || defaultApi;
  window.SENTINELAPI_IS_HOSTED = !fileFrontend && !loopbackHost;
})();
