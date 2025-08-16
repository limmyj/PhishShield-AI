function injectBanner(data) {
  const bannerId = "MalCommandGuard-banner";
  if (document.getElementById(bannerId)) return;

  const banner = document.createElement("div");
  banner.id = bannerId;

  const verdict = data.verdict || "Unknown";
  const confidence = (data.confidence * 100).toFixed(2) || "N/A";
  const verdictText = `${verdict} (${confidence}%)`;

  let bgColor = "#ffeb3b"; // Yellow default
  const verdictLower = (data.verdict || "").toLowerCase();
  if (verdictLower === "phishing") bgColor = "#ff5252";
  else if (verdictLower === "legitimate") bgColor = "#8bc34a";

  Object.assign(banner.style, {
    position: "fixed",
    top: "0",
    left: "0",
    right: "0",
    zIndex: "999999",
    backgroundColor: bgColor,
    color: "#000",
    padding: "12px 16px",
    fontSize: "16px",
    fontWeight: "bold",
    boxShadow: "0 2px 6px rgba(0,0,0,0.2)",
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    });

  banner.innerHTML = `
    <span>🛡️ MalCommandGuard Verdict: <strong>${verdictText}</strong></span>
    <span>
      <a href="#" id="MalCommandGuard-moreinfo" style="margin-right: 15px; text-decoration: underline; color: blue;">More Info</a>
      <button id="MalCommandGuard-dismiss" style="background: transparent; border: none; font-weight: bold; cursor: pointer;">Dismiss</button>
    </span>
  `;

  document.body.appendChild(banner);

  document.getElementById("MalCommandGuard-dismiss").addEventListener("click", () => {
    banner.remove();
  });

  document.getElementById("MalCommandGuard-moreinfo").addEventListener("click", (e) => {
    e.preventDefault();
    chrome.runtime.sendMessage({ action: "open_report_page" });
  });
}

chrome.runtime.onMessage.addListener((message) => {
  if (message.action === "new_url_scan_result") {
    const data = message.data;
    const currentUrl = window.location.href;

    if (data && data.url && new URL(currentUrl).hostname === new URL(data.url).hostname) {
      injectBanner(data);
    }
  }
});

