document.addEventListener("DOMContentLoaded", () => {
  const reportDiv = document.getElementById("report");
  const printBtn = document.getElementById("printBtn");

  chrome.storage.local.get("latestUrlReport", (res) => {
    const data = res.latestUrlReport;
    if (!data || !data.features) {
      reportDiv.innerHTML = "<p>No scan data available.</p>";
      return;
    }

    const phishingProb = (data.phishing_probability * 100).toFixed(2);
    const rawVerdict = data.verdict || "Unknown";
    const verdict = rawVerdict.toLowerCase();

    const features = data.features?.resolved_features || data.features?.original_features || {};
    const cleanedFeatures = { ...features };
    const url = features.original_url || data.url || features.url || "-";
    const domain = features.resolved_domain || features.original_domain || features.url_domain || "-";
    const checkedAt = new Date().toLocaleString();

    const stripFields = [
      "IP Address", "SSL Issuer", "Valid From", "Valid To",
      "Domain Age", "SSL Certificate Valid", "uses_https"
    ];
    stripFields.forEach(key => delete cleanedFeatures[key]);

    let verdictEmoji = "❓", verdictClass = "verdict-box";
    if (verdict === "phishing") {
      verdictEmoji = "🛑"; verdictClass += " verdict-phishing";
    } else if (verdict === "suspicious") {
      verdictEmoji = "⚠️"; verdictClass += " verdict-suspicious";
    } else if (verdict === "legitimate") {
      verdictEmoji = "🛡️"; verdictClass += " verdict-legit";
    }

    const verdictHTML = `
      <div class="${verdictClass}">
        <b>Verdict:</b> ${verdictEmoji} ${rawVerdict}<br>
        <b>Phishing Probability:</b> ${phishingProb}%
      </div>`;

    const featureTable = `
      <h2>🔎 URL Feature Breakdown</h2>
      <table><tr><th>Feature</th><th>Value</th></tr>
        ${Object.entries(cleanedFeatures).map(([k, v]) => `<tr><td>${k}</td><td>${v}</td></tr>`).join("")}
      </table>`;
    
    const metadataTable = `
      <h2>🌐 WHOIS & SSL Metadata</h2>
      <table>
        <tr><td><b>Checked At</b></td><td>${checkedAt}</td></tr>
        <tr><td><b>HTTPS Used</b></td><td>${features.uses_https ? "Yes" : "No"}</td></tr>
        <tr><td><b>SSL Certificate Valid</b></td><td>${features["SSL Certificate Valid"] ? "Yes" : "No"}</td></tr>
        <tr><td><b>SSL Issuer</b></td><td>${features["SSL Issuer"] || "Unknown"}</td></tr>
        <tr><td><b>Valid From</b></td><td>${features["Valid From"] || "Unknown"}</td></tr>
        <tr><td><b>Valid To</b></td><td>${features["Valid To"] || "Unknown"}</td></tr>
        <tr><td><b>IP Address</b></td><td>${features["IP Address"] || "Unavailable"}</td></tr>
        <tr><td><b>Domain Age</b></td><td>${features["Domain Age"] || "Unknown"}</td></tr>
      </table>`;

    reportDiv.innerHTML = `${verdictHTML}${featureTable}${metadataTable}`;
  });

  printBtn?.addEventListener("click", () => window.print());
});
