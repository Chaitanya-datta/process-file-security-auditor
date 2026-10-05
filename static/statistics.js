// Statistics page: counts computed by the server from the logged alerts.

function render(data) {
  const stats = data.statistics;
  byId("s-total").textContent = stats.total_alerts;
  byId("s-combined").textContent = stats.combined_alerts;
  byId("s-suppressed").textContent = data.header.suppressed_duplicates;
  renderBars("by-severity", stats.by_severity);
  renderBars("by-detection", stats.by_detection);
}

startRefresh("/api/statistics", render);
