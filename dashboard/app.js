const PAGE_SIZE = 25;
let currentOffset = 0;
let currentTotal = 0;
let alertOffset = 0;
let alertTotal = 0;
const byId = (id) => document.getElementById(id);
const fmt = new Intl.NumberFormat();

async function getJson(url) {
  const response = await fetch(url, { headers: { Accept: "application/json" } });
  if (!response.ok) {
    const detail = response.status === 503 ? "Database unavailable. Check the API configuration." : `Request failed (${response.status}).`;
    throw new Error(detail);
  }
  return response.json();
}

function setConnection(connected, message) {
  const label = byId("connection-label");
  label.textContent = message;
  label.parentElement.classList.toggle("connection-error", !connected);
}

function escapeText(value) {
  return value == null || value === "" ? "—" : String(value);
}

function formatTime(value) {
  if (!value) return "—";
  return new Date(value).toLocaleString([], { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

function renderActivity(points) {
  const svg = byId("activity-chart");
  const width = 720, height = 230, left = 36, right = 12, top = 12, bottom = 27;
  const plotWidth = width - left - right, plotHeight = height - top - bottom;
  const currentHour = new Date(); currentHour.setMinutes(0, 0, 0);
  const byHour = new Map(points.map((point) => [Math.floor(new Date(point.hour).getTime() / 3600000), point]));
  const series = Array.from({ length: 24 }, (_, index) => {
    const hourDate = new Date(currentHour.getTime() - (23 - index) * 3600000);
    const point = byHour.get(Math.floor(hourDate.getTime() / 3600000));
    return { label: hourDate.toLocaleTimeString([], { hour: "2-digit", hour12: false }), total: Number(point?.total || 0), failures: Number(point?.failures || 0) };
  });
  const max = Math.max(5, ...series.map((point) => point.total));
  const x = (index) => left + index * plotWidth / (series.length - 1);
  const y = (value) => top + plotHeight - value / max * plotHeight;
  const line = (key) => series.map((point, index) => `${index ? "L" : "M"}${x(index).toFixed(1)},${y(point[key]).toFixed(1)}`).join(" ");
  const areaPath = `${line("total")} L${x(23)},${top + plotHeight} L${left},${top + plotHeight} Z`;
  const grid = [0, .33, .66, 1].map((ratio) => {
    const gy = top + plotHeight * ratio;
    const value = Math.round(max * (1 - ratio));
    return `<line class="chart-grid" x1="${left}" x2="${width - right}" y1="${gy}" y2="${gy}"/><text class="chart-label" x="${left - 8}" y="${gy + 3}" text-anchor="end">${value}</text>`;
  }).join("");
  const labels = [0, 6, 12, 18, 23].map((index) => `<text class="chart-label" x="${x(index)}" y="${height - 5}" text-anchor="middle">${series[index].label}</text>`).join("");
  svg.innerHTML = `<defs><linearGradient id="activity-fill" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stop-color="#5ee0d0" stop-opacity=".19"/><stop offset="100%" stop-color="#5ee0d0" stop-opacity="0"/></linearGradient></defs>${grid}<path class="chart-area" d="${areaPath}"/><path class="chart-line" d="${line("total")}"/><path class="chart-fail-line" d="${line("failures")}"/>${labels}`;
}

function renderBars(target, items, labelKey, valueKey, className = "") {
  const container = byId(target);
  if (!items.length) {
    container.innerHTML = '<div class="empty-state">No activity in this period</div>';
    return;
  }
  const max = Math.max(1, ...items.map((item) => Number(item[valueKey])));
  container.replaceChildren(...items.map((item) => {
    const row = document.createElement("div"); row.className = "bar-item";
    const label = document.createElement("span"); label.className = "bar-label"; label.textContent = escapeText(item[labelKey]);
    const track = document.createElement("span"); track.className = "bar-track";
    const fill = document.createElement("span"); fill.className = `bar-fill ${className}`; fill.style.width = `${Math.max(3, Number(item[valueKey]) / max * 100)}%`; track.append(fill);
    const value = document.createElement("span"); value.className = "bar-value"; value.textContent = fmt.format(item[valueKey]);
    row.append(label, track, value); return row;
  }));
}

function renderAlerts(alerts) {
  const list = byId("alerts-list");
  if (!alerts.length) { list.innerHTML = '<div class="empty-state">No open security alerts</div>'; return; }
  list.replaceChildren(...alerts.slice(0, 6).map((alert) => {
    const row = document.createElement("div"); row.className = "alert-row";
    const dot = document.createElement("span"); dot.className = `alert-severity sev-${alert.severity}`;
    const body = document.createElement("div");
    const title = document.createElement("div"); title.className = "alert-title"; title.textContent = alert.alert_type.replaceAll("_", " ");
    const detail = document.createElement("div"); detail.className = "alert-desc"; detail.textContent = alert.description;
    body.append(title, detail);
    const time = document.createElement("span"); time.className = "alert-time"; time.textContent = formatTime(alert.created_at);
    row.append(dot, body, time); return row;
  }));
}

function renderEvents(events) {
  const table = byId("events-table");
  if (!events.length) { table.innerHTML = '<tr><td colspan="7" class="empty-state">No events match these filters</td></tr>'; return; }
  table.replaceChildren(...events.map((event) => {
    const tr = document.createElement("tr");
    const values = [formatTime(event.event_time), event.username, event.source_ip, event.country, event.device, event.login_method];
    values.forEach((value, index) => { const td = document.createElement("td"); td.textContent = escapeText(value); if (index === 1) td.className = "user-cell"; if (index === 2) td.className = "ip-cell"; tr.append(td); });
    const result = document.createElement("td");
    const badge = document.createElement("span"); badge.className = `result-badge result-${event.status.toLowerCase()}`; badge.textContent = event.status;
    result.append(badge);
    if (event.failure_reason) { const reason = document.createElement("span"); reason.className = "failure-reason"; reason.textContent = event.failure_reason.replaceAll("_", " "); result.append(reason); }
    tr.append(result); return tr;
  }));
}

function renderAlertTable(alerts) {
  const table = byId("alerts-table");
  if (!alerts.length) { table.innerHTML = '<tr><td colspan="7" class="empty-state">No alerts match these filters</td></tr>'; return; }
  table.replaceChildren(...alerts.map((alert) => {
    const tr = document.createElement("tr");
    const values = [formatTime(alert.created_at), alert.alert_type.replaceAll("_", " "), alert.severity, alert.username, alert.source_ip, alert.status.replaceAll("_", " ")];
    values.forEach((value, index) => {
      const td = document.createElement("td"); td.textContent = escapeText(value);
      if (index === 2) { const badge = document.createElement("span"); badge.className = `severity-badge sev-${alert.severity}`; badge.textContent = alert.severity; td.replaceChildren(badge); }
      if (index === 4) td.className = "ip-cell";
      tr.append(td);
    });
    const description = document.createElement("td"); description.className = "description-cell"; description.textContent = alert.description; description.title = alert.description; tr.append(description);
    return tr;
  }));
}

function filterUrl() {
  const params = new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(currentOffset) });
  const username = byId("filter-username").value.trim();
  const status = byId("filter-status").value;
  const ip = byId("filter-ip").value.trim();
  if (username) params.set("username", username);
  if (status) params.set("status", status);
  if (ip) params.set("source_ip", ip);
  return `/login-events?${params}`;
}

async function loadEvents() {
  const response = await fetch(filterUrl(), { headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error(response.status === 503 ? "Database unavailable. Check the API configuration." : `Request failed (${response.status}).`);
  currentTotal = Number(response.headers.get("X-Total-Count") || 0);
  const events = await response.json();
  renderEvents(events);
  byId("event-count").textContent = `${fmt.format(currentTotal)} matching`;
  const first = currentTotal ? currentOffset + 1 : 0;
  const last = Math.min(currentOffset + PAGE_SIZE, currentTotal);
  byId("pagination-label").textContent = `Showing ${fmt.format(first)}–${fmt.format(last)} of ${fmt.format(currentTotal)}`;
  byId("previous-page").disabled = currentOffset === 0;
  byId("next-page").disabled = currentOffset + PAGE_SIZE >= currentTotal;
}

async function loadAlertTable() {
  const params = new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(alertOffset) });
  if (byId("alert-status-filter").value) params.set("status", byId("alert-status-filter").value);
  if (byId("alert-severity-filter").value) params.set("severity", byId("alert-severity-filter").value);
  const response = await fetch(`/security-alerts?${params}`, { headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error(response.status === 503 ? "Database unavailable. Check the API configuration." : `Request failed (${response.status}).`);
  alertTotal = Number(response.headers.get("X-Total-Count") || 0);
  renderAlertTable(await response.json());
  byId("alert-count").textContent = `${fmt.format(alertTotal)} matching`;
  byId("alert-pagination-label").textContent = `Showing ${fmt.format(alertTotal ? alertOffset + 1 : 0)}–${fmt.format(Math.min(alertOffset + PAGE_SIZE, alertTotal))} of ${fmt.format(alertTotal)}`;
  byId("previous-alert-page").disabled = alertOffset === 0;
  byId("next-alert-page").disabled = alertOffset + PAGE_SIZE >= alertTotal;
}

async function refreshDashboard() {
  byId("refresh-button").classList.add("is-loading");
  try {
    const [summary, alerts] = await Promise.all([getJson("/summary"), getJson("/security-alerts?status=OPEN&limit=10")]);
    byId("kpi-events").textContent = fmt.format(summary.events_24h);
    byId("kpi-failures").textContent = fmt.format(summary.failures_24h);
    byId("kpi-alerts").textContent = fmt.format(summary.open_alerts);
    byId("kpi-users").textContent = fmt.format(summary.users_24h);
    const severities = summary.open_alerts_by_severity || [];
    byId("kpi-severity").textContent = severities.length ? severities.map((item) => `${item.severity}: ${item.total}`).join(" · ") : "No open alerts";
    renderActivity(summary.hourly || []);
    renderBars("ip-bars", summary.top_failed_ips || [], "source_ip", "failures", "ip-fill");
    renderBars("country-bars", summary.countries || [], "country", "total");
    renderAlerts(alerts);
    await Promise.all([loadEvents(), loadAlertTable()]);
    setConnection(true, "Database connected");
    byId("last-updated").textContent = `Updated ${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
  } catch (error) {
    setConnection(false, "Database disconnected");
    byId("alerts-list").innerHTML = `<div class="empty-state">${error.message}</div>`;
    byId("events-table").innerHTML = `<tr><td colspan="7" class="empty-state">${error.message}</td></tr>`;
    byId("alerts-table").innerHTML = `<tr><td colspan="7" class="empty-state">${error.message}</td></tr>`;
  } finally {
    byId("refresh-button").classList.remove("is-loading");
  }
}

byId("filters").addEventListener("submit", (event) => { event.preventDefault(); currentOffset = 0; loadEvents().catch((error) => { byId("events-table").innerHTML = `<tr><td colspan="7" class="empty-state">${error.message}</td></tr>`; }); });
byId("clear-filters").addEventListener("click", () => { byId("filters").reset(); currentOffset = 0; loadEvents().catch(() => {}); });
byId("previous-page").addEventListener("click", () => { currentOffset = Math.max(0, currentOffset - PAGE_SIZE); loadEvents().catch(() => {}); });
byId("next-page").addEventListener("click", () => { currentOffset += PAGE_SIZE; loadEvents().catch(() => {}); });
byId("alert-filters").addEventListener("submit", (event) => { event.preventDefault(); alertOffset = 0; loadAlertTable().catch((error) => { byId("alerts-table").innerHTML = `<tr><td colspan="7" class="empty-state">${error.message}</td></tr>`; }); });
byId("clear-alert-filters").addEventListener("click", () => { byId("alert-filters").reset(); alertOffset = 0; loadAlertTable().catch(() => {}); });
byId("previous-alert-page").addEventListener("click", () => { alertOffset = Math.max(0, alertOffset - PAGE_SIZE); loadAlertTable().catch(() => {}); });
byId("next-alert-page").addEventListener("click", () => { alertOffset += PAGE_SIZE; loadAlertTable().catch(() => {}); });
function setLiveState(connected, message) {
  const pill = byId("live-pill");
  pill.classList.toggle("is-live", connected);
  pill.classList.toggle("is-offline", !connected);
  pill.innerHTML = `<span class="range-dot"></span>${message}`;
}

function startLiveFeed() {
  const source = new EventSource("/live");
  source.addEventListener("ready", () => setLiveState(true, "Live from staff portal"));
  source.onmessage = () => {
    setLiveState(true, "Live · event received");
    refreshDashboard();
  };
  source.onerror = () => setLiveState(false, "Live feed reconnecting");
}

byId("refresh-button").addEventListener("click", refreshDashboard);
refreshDashboard();
startLiveFeed();
setInterval(refreshDashboard, 8000);
