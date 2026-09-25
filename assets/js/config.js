(() => {
  const localFrontend = location.protocol === "file:" || location.port === "5500";
  const defaultApi = localFrontend ? "http://127.0.0.1:8000" : location.origin;
  window.SENTINEL_API_URL = window.SENTINEL_API_URL || defaultApi;
})();
