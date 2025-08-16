let lastNotificationId = null;
let lastNotificationType = null;
const scannedUrls = new Set();

function updateBadge(status) {
  let text = "?";
  let color = "gray";

  if (status === "Phishing") {
    text = "☠️";
    color = "red";
  } else if (status === "Suspicious") {
    text = "⚠️";
    color = "orange";
  } else if (status === "Legitimate") {
    text = "✅";
    color = "green";
  }

  chrome.action.setBadgeText({ text });
  chrome.action.setBadgeBackgroundColor({ color });
}

function showScanNotification(url, verdict, confidence) {
  const confPercent = (confidence > 1 ? confidence : confidence * 100).toFixed(2);
  const icon = verdict === "Phishing" ? "🛑" :
               verdict === "Suspicious" ? "⚠️" :
               verdict === "Legitimate" ? "🛡️" : "❓";

  chrome.notifications.create({
    type: "basic",
    iconUrl: "icon.png",
    title: `MalCommandGuard Website Scan ${icon}`,
    message: `Status: ${verdict}\nConfidence: ${confPercent}%`,
    priority: 2
  }, (notifId) => {
    lastNotificationId = notifId;
    lastNotificationType = "site";
  });
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "get_latest_url_report") {
    chrome.storage.local.get("latestUrlReport", (res) => {
      sendResponse(res.latestUrlReport || null);
    });
    return true; // Keep message channel open for async sendResponse
  }
  
  if (message.action === "showNotification" && message.payload) {
    const { title, message: msg, icon, type } = message.payload;
    const notifTitle = title || (type === "email" ? "MalCommandGuard Email Scan" : "MalCommandGuard Website Scan");
    const isEmail = type === "email" || notifTitle.toLowerCase().includes("email");

    chrome.notifications.create({
      type: "basic",
      iconUrl: icon || "icon.png",
      title: notifTitle,
      message: msg || "A new item was scanned.",
      priority: 2
    }, (notifId) => {
      if (type === "email") {
        lastNotificationId = notifId;
        lastNotificationType = "email";
      } else {
        lastNotificationId = notifId;
        lastNotificationType = "site";
      }
    });
  }

  if (message.action === "open_report_page") {
    chrome.tabs.create({
      url: chrome.runtime.getURL("url_report.html")
    });
  }
});

chrome.notifications.onClicked.addListener((notifId) => {
  if (!notifId || notifId !== lastNotificationId) return;

  if (lastNotificationType === "email") {
    chrome.windows.create({
      url: chrome.runtime.getURL("popup.html"),
      type: "popup",
      width: 380,
      height: 620
    });
  } else {
    chrome.tabs.create({
      url: chrome.runtime.getURL("url_report.html")
    });
  }
});

chrome.action.onClicked.addListener((tab) => {
  const url = tab.url || "";

  if (url.includes("mail.google.com")) {
    chrome.windows.create({
      url: chrome.runtime.getURL("popup.html"),
      type: "popup",
      width: 380,
      height: 620
    });
  } else {
    chrome.windows.create({
      url: chrome.runtime.getURL("website_popup.html"),
      type: "popup",
      width: 380,
      height: 520
    });
  }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (
    changeInfo.status === "complete" &&
    tab.url?.startsWith("http") &&
    !tab.url.includes("mail.google.com") &&
    !tab.url.includes("127.0.0.1")
  ) {
    const cleanedUrl = tab.url.split("#")[0];
    if (scannedUrls.has(cleanedUrl)) return;
    scannedUrls.add(cleanedUrl);

    fetch("http://127.0.0.1:5000/api/scan_site", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: cleanedUrl })
    })
    .then(res => res.json())
    .then(data => {
      updateBadge(data.verdict);
      showScanNotification(cleanedUrl, data.verdict, data.confidence);
      chrome.storage.local.set({ latestUrlReport: { ...data, source: "tab" } });

      chrome.tabs.sendMessage(tabId, {
        action: "new_url_scan_result",
        data: { ...data, url: cleanedUrl },
      });
    })
    .catch(console.error);
  }
});