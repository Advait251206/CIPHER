/**
 * CIPHER Browser Guard — Warning Page Controller
 * Reads URL parameters for threat details and binds navigation buttons.
 */

document.addEventListener("DOMContentLoaded", () => {
  const urlParams = new URLSearchParams(window.location.search);
  const target = urlParams.get("target") || "Unknown target";
  const risk = urlParams.get("risk") || "90";
  const severity = urlParams.get("severity") || "CRITICAL";
  const conf = urlParams.get("confidence") || "95";
  const reasonsParam = urlParams.get("reasons");

  document.getElementById("targetUrl").textContent = target;
  document.getElementById("riskVal").textContent = `${risk} / 100`;
  document.getElementById("severityVal").textContent = severity;
  document.getElementById("confVal").textContent = `${conf}%`;

  if (reasonsParam) {
    try {
      const reasons = JSON.parse(decodeURIComponent(reasonsParam));
      const listEl = document.getElementById("evidenceList");
      listEl.innerHTML = "";
      reasons.forEach((r) => {
        const li = document.createElement("li");
        li.textContent = r;
        listEl.appendChild(li);
      });
    } catch (e) {
      // Fallback to default
    }
  }

  document.getElementById("backBtn").addEventListener("click", () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.close();
    }
  });

  document.getElementById("proceedBtn").addEventListener("click", () => {
    if (target && target.startsWith("http")) {
      window.location.href = target;
    }
  });
});
