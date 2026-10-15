const BASE = "/api";

async function request(path, options) {
  const res = await fetch(BASE + path, options);
  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(body.detail || `request failed (${res.status})`);
  }
  return res.json();
}

export const api = {
  fixtures: () => request("/fixtures"),
  scans: () => request("/scans"),
  scan: (id) => request(`/scans/${id}`),
  createScan: (path, runExternal, refresh) =>
    request("/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path, run_external: runExternal, refresh: !!refresh }),
    }),
  verify: (findingId) =>
    request(`/findings/${findingId}/verify`, { method: "POST" }),
  patch: (findingId) => request(`/findings/${findingId}/patch`),
  applyPatch: (findingId) =>
    request(`/findings/${findingId}/apply`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ confirm: true }),
    }),
  reportUrl: (id, fmt) => `${BASE}/scans/${id}/report.${fmt}`,
};
