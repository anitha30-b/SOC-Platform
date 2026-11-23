/** Shared browser endpoints for development and company-server deployments. */
export function resolveDeploymentEndpoints(env = {}, browserOrigin = "http://localhost") {
  const origin = new URL(browserOrigin);
  if (!["http:", "https:"].includes(origin.protocol)) {
    throw new Error("The frontend requires an HTTP or HTTPS origin.");
  }
  const configured = String(env.VITE_API_BASE_URL || env.VITE_API_URL || "").trim();
  const api = new URL(configured || (env.DEV === true ? "http://127.0.0.1:8000" : "/api"), origin);
  if (!["http:", "https:"].includes(api.protocol) || api.username || api.password || api.search || api.hash) {
    throw new Error("Invalid frontend API base configuration.");
  }
  const socket = env.VITE_WS_BASE_URL ? new URL(String(env.VITE_WS_BASE_URL).trim(), origin) : new URL(api);
  if (socket.protocol === "http:") socket.protocol = "ws:";
  if (socket.protocol === "https:") socket.protocol = "wss:";
  if (!["ws:", "wss:"].includes(socket.protocol) || socket.username || socket.password || socket.search || socket.hash) {
    throw new Error("Invalid frontend WebSocket base configuration.");
  }
  if (origin.protocol === "https:" && (api.protocol !== "https:" || socket.protocol !== "wss:")) {
    throw new Error("HTTPS deployments require HTTPS API and WSS WebSocket endpoints.");
  }
  return Object.freeze({ API_BASE_URL: api.href.replace(/\/+$/, ""), WS_BASE_URL: socket.href.replace(/\/+$/, "") });
}

const browserOrigin = typeof window === "undefined" ? "http://localhost" : window.location.origin;
export const { API_BASE_URL, WS_BASE_URL } = resolveDeploymentEndpoints(import.meta.env || {}, browserOrigin);
