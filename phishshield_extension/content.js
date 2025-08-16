console.log("✅ MalCommandGuard banner.js loaded!");

let lastExtracted = "";
let debounceTimer = null;

function cleanUrl(raw) {
  return raw.trim().replace(/([\]\)]+|\s+)+$/, "");
}

function extractSenderDetails() {
  const headerBlock = document.querySelector(".adn, .h7") || document.querySelector(".gE.hP");
  const senderEl = headerBlock?.querySelector("span[email]");
  const fallbackNameEl = headerBlock?.querySelector(".go") || headerBlock?.querySelector(".gD");

  const email = senderEl?.getAttribute("email") || "unknown@example.com";
  let name = senderEl?.innerText?.trim();
  if (!name && fallbackNameEl) name = fallbackNameEl.innerText?.trim();
  if (!name) name = "Unknown Sender";

  return { email, name };
}

function extractEmailSubject() {
  const subjectEl = document.querySelector("h2.hP");
  return subjectEl ? subjectEl.innerText.trim() : "No Subject";
}

function extractLinks(container) {
  if (!container) return [];

  const anchors = Array.from(container.querySelectorAll("a"));
  const links = anchors.map(anchor => {
    const saferRedirect = anchor.getAttribute("data-saferedirecturl");
    if (saferRedirect?.includes("https://www.google.com/url?q=")) {
      try {
        const url = new URL(saferRedirect);
        const real = url.searchParams.get("q");
        if (real) return cleanUrl(decodeURIComponent(real));
      } catch (e) {
        console.warn("Invalid redirect URL", saferRedirect);
      }
    }

    const href = anchor.getAttribute("href");
    return href?.startsWith("http") ? cleanUrl(href) : null;
  });

  return [...new Set(links.filter(Boolean))]; 
}

function getInterceptedLinks(container) {
  const anchors = container.querySelectorAll("a");
  const links = [];

  anchors.forEach(anchor => {
    let displayUrl = null;

    const saferRedirect = anchor.getAttribute("data-saferedirecturl");
    if (saferRedirect?.includes("https://www.google.com/url?q=")) {
      try {
        const url = new URL(saferRedirect);
        const real = url.searchParams.get("q");
        if (real) displayUrl = cleanUrl(decodeURIComponent(real));
      } catch {}
    } else {
      const href = anchor.getAttribute("href");
      if (href?.startsWith("http")) {
        displayUrl = cleanUrl(href);
      }
    }

    if (displayUrl && !links.includes(displayUrl)) {
      links.push(displayUrl);
    }
  });

  return links;
}

function extractEmailContent(attempts = 15) {
  const emailElement =
    document.querySelector(".ii.gt .a3s") ||
    document.querySelector(".ii.gt") ||
    document.querySelector(".a3s");

  const headerBlock = document.querySelector(".adn, .h7") || document.querySelector(".gE.hP");

  if (!emailElement || !headerBlock) {
    if (attempts > 0) {
      console.warn("❌ Email element or header not ready, retrying...");
      return setTimeout(() => extractEmailContent(attempts - 1), 1000);
    } else {
      chrome.runtime.sendMessage({ action: "clearStorage" });
      return;
    }
  }

  let timestampEl = document.querySelector('span.g3') || document.querySelector('span.gH .gK');
  let timestamp = Date.now(); 

  if (timestampEl?.getAttribute('title')) {
    let raw = timestampEl.getAttribute('title'); 
    raw = raw.replace(/\u202f/g, ' ').replace(/\s+/g, ' ').trim();
    const parsed = new Date(raw);
    if (!isNaN(parsed.getTime())) {
      timestamp = parsed.getTime(); 
    } else {
      console.warn("⚠️ Could not parse Gmail timestamp:", raw);
    }
  }

  const emailText = emailElement.innerText?.trim() || "";
  if (!emailText || emailText === lastExtracted) {
    chrome.runtime.sendMessage({ action: "clearStorage" });
    return;
  }

  lastExtracted = emailText;
  chrome.storage.local.remove(["lastResult"]);

  const extractedLinks = getInterceptedLinks(emailElement);
  const { email, name } = extractSenderDetails();
  const subject = extractEmailSubject();

  const emailData = {
    emailText,
    senderEmail: email,
    senderName: name,
    subject,
    extractedLinks
  };

  chrome.storage.local.set({ extractedEmail: emailData });

  injectHighlightStyle();
  const emailContainer = document.querySelector(".ii.gt, .a3s.aXjCH");
  const subjectEl = document.querySelector("h2.hP");

  fetch("http://127.0.0.1:5000/api/spam_keywords")
    .then(res => res.json())
    .then(data => {
      const spamKeywords = data.keywords || [];
      if (emailContainer) highlightSuspiciousKeywords(emailContainer, spamKeywords);
      if (subjectEl) highlightSuspiciousKeywords(subjectEl, spamKeywords);
    });

  interceptEmailLinks(emailElement, extractedLinks);

  fetch("http://127.0.0.1:5000/api/check", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email_text: emailText,
      sender: email,
      sender_name: name,
      subject,
      extracted_urls: extractedLinks,
      email_timestamp: timestamp / 1000
    })
  })
  .then(async response => {
    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Backend error: ${response.status} - ${text}`);
    }
    return response.json();
  })
  .then(data => {
    chrome.storage.local.set({ lastResult: { ...data, source: "email" } });

    if (data?.final_decision) {
      const label = data.email_label || data.final_decision || "Unknown";
      const confidence = data.email_confidence ?? data.confidence ?? 0;
      const shownConfidence = (confidence > 1 ? confidence : confidence * 100).toFixed(2);
      chrome.runtime.sendMessage({
        action: "showNotification",
        payload: {
          title: "MalCommandGuard Email Scan",
          message: `Status: ${label} (${shownConfidence}%)`,
          icon: "icon.png",
          type: "email"
        }
      });
    }
  })
  .catch(err => console.error("❌ Backend fetch failed:", err));
}

function interceptEmailLinks(container, linksForAnalysis = []) {
  if (!container) return;

  const anchors = container.querySelectorAll("a");
  anchors.forEach(anchor => {
    let displayUrl = null;

    const saferRedirect = anchor.getAttribute("data-saferedirecturl");
    if (saferRedirect?.includes("https://www.google.com/url?q=")) {
      try {
        const url = new URL(saferRedirect);
        const real = url.searchParams.get("q");
        if (real) displayUrl = cleanUrl(decodeURIComponent(real));
      } catch {}
    } else {
      const href = anchor.getAttribute("href");
      if (href?.startsWith("http")) {
        displayUrl = cleanUrl(href);
      }
    }

    if (!displayUrl || !linksForAnalysis.includes(displayUrl)) return;

    anchor.onclick = e => {
      e.preventDefault();
      e.stopPropagation();

      const confirmMsg = `⚠️ Warning: You are about to open this link:\n\n${displayUrl}\n\nAre you sure you want to proceed?`;
      if (confirm(confirmMsg)) {
        window.open(displayUrl, "_blank", "noopener");
      }
    };

    anchor.style.borderBottom = "2px dashed red";
    anchor.style.color = "#c40000";
  });
}

function highlightSuspiciousKeywords(container, keywords) {
  if (!container || keywords.length === 0) return;
  const safeKeywords = keywords.map(kw =>
    kw.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
  );
  const keywordRegex = new RegExp(`\\b(${safeKeywords.join("|")})\\b`, "gi");
  const walker = document.createTreeWalker(container, NodeFilter.SHOW_TEXT, null, false);
  const nodesToHighlight = [];
  while (walker.nextNode()) {
    const node = walker.currentNode;
    if (keywordRegex.test(node.textContent)) {
      nodesToHighlight.push(node);
    }
  }
  nodesToHighlight.forEach(node => {
    const parent = node.parentNode;
    const text = node.textContent;
    const fragments = [];
    let lastIndex = 0;
    text.replace(keywordRegex, (match, _, offset) => {
      if (offset > lastIndex) {
        fragments.push(document.createTextNode(text.slice(lastIndex, offset)));
      }
      const span = document.createElement("span");
      span.className = "phish-highlight";
      span.textContent = match;
      fragments.push(span);
      lastIndex = offset + match.length;
    });
    if (lastIndex < text.length) {
      fragments.push(document.createTextNode(text.slice(lastIndex)));
    }
    fragments.forEach(fragment => parent.insertBefore(fragment, node));
    parent.removeChild(node);
  });
}

function injectHighlightStyle() {
  if (document.getElementById("phish-style")) return;
  const style = document.createElement("style");
  style.id = "phish-style";
  style.innerHTML = `
    .phish-highlight {
      background-color: yellow;
      font-weight: bold;
      color: red;
      padding: 0 2px;
      border-radius: 3px;
    }
  `;
  document.head.appendChild(style);
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "triggerExtract") {
    extractEmailContent();
    sendResponse({ status: "running" });
  }
});

const observer = new MutationObserver(() => {
  const emailBody = document.querySelector(".ii.gt");
  const headerBlock = document.querySelector(".adn, .h7") || document.querySelector(".gE.hP");

  const inEmailView = !!(emailBody && headerBlock);
  if (inEmailView) {
    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      const fullText = emailBody.innerText?.trim() || "";
      if (fullText.length > 30 && fullText !== lastExtracted) {
        extractEmailContent();
      }
    }, 1000);
  }
});

observer.observe(document.body, {
  childList: true,
  subtree: true
});