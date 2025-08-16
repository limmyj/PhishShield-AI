document.addEventListener('DOMContentLoaded', () => {
  const verdictIcon = document.getElementById('verdict');
  const summaryTag = document.getElementById('summaryTag');
  const shortSummary = document.getElementById('shortSummary');
  const badgeLinks = document.getElementById('badgeLinks');
  const badgeSpam = document.getElementById('badgeSpamKeywords');
  const urlCards = document.getElementById('urlCards');
  const statusMessage = document.getElementById('statusMessage');
  const viewBtn = document.getElementById('viewDetailsBtn');

  document.addEventListener('click', (e) => {
    if (e.target.closest('.dropdown')) {
      e.target.closest('.dropdown').classList.toggle('open');
    }
  });

  chrome.storage.local.get(['lastResult'], (res) => {
    if (res?.lastResult) {
      console.log("✅ Showing cached result (from lastResult)");
      displayResults(res.lastResult);
    } else {
      console.warn("⚠️ No cached result found, likely not ready");

      statusMessage.innerHTML = '<span style="color:orange;">⏳ Email analysis not ready. Please wait a moment or refresh email.</span>';

      chrome.storage.local.get(['extractedEmail'], (res2) => {
        if (res2?.extractedEmail) {
          console.warn("⚠️ Email content exists but no result yet — retrying backend analysis");
          fetchAnalysis(res2.extractedEmail);
        }
      });
    }
  });

  function fetchAnalysis(content) {
    const senderEmail = content.senderEmail || "unknown@example.com";
    const senderName = content.senderName || "Unknown Sender";

    fetch('http://127.0.0.1:5000/api/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email_text: content.emailText,
        sender: senderEmail,
        sender_name: senderName
      })
    })
    .then(res => res.json())
    .then(data => {
      chrome.storage.local.set({ lastResult: data });
      displayResults(data);
    })
    .catch(err => {
      console.error("❌ Backend error from popup.js:", err);
      verdictIcon.innerText = "❓";
      verdictIcon.className = "circle-verdict";
      summaryTag.innerText = "❌ Error";
      shortSummary.innerText = "";
      statusMessage.innerHTML = '<span style="color:red;">🚫 Backend error or email not ready.</span>';
    });
  }

  function displayResults(data) {
    const { url_predictions, spam_keyword_count } = data;

    let phishingCount = 0;
    let suspiciousCount = 0;

    Object.values(url_predictions || {}).forEach(pred => {
      if (pred.label === "Phishing") phishingCount++;
      else if (pred.label === "Suspicious") suspiciousCount++;
    });

    let finalURLVerdict = "✅ Legitimate";
    if (phishingCount > 0) {
      finalURLVerdict = "☠️ Phishing Detected";
      verdictIcon.innerText = "☠️";
      verdictIcon.className = "circle-verdict verdict-phishing";
    } else if (suspiciousCount > 0) {
      finalURLVerdict = "⚠️ Suspicious Link";
      verdictIcon.innerText = "⚠️";
      verdictIcon.className = "circle-verdict verdict-suspicious";
    } else {
      verdictIcon.innerText = "✅";
      verdictIcon.className = "circle-verdict verdict-legit";
    }

    summaryTag.innerText = finalURLVerdict;
    badgeLinks.innerText = `Links found: ${Object.keys(url_predictions || {}).length}`;
    badgeSpam.innerText = `Spam keywords: ${spam_keyword_count || 0}`;

    urlCards.innerHTML = '';
    Object.entries(url_predictions || {}).forEach(([url, { label, confidence }]) => {
      const className = label === "Phishing" ? 'url-phish' :
                        label === "Suspicious" ? 'url-suspicious' : 'url-legit';
      const card = document.createElement('div');
      card.className = `url-box ${className}`;
      card.innerHTML = `<div class="url-meta"><span>${url}</span><br><b>${label}</b> (${confidence}%)</div>`;
      urlCards.appendChild(card);
    });
  }

  if (viewBtn) {
    viewBtn.addEventListener('click', () => {
      chrome.tabs.create({ url: 'http://127.0.0.1:5000/details' });
    });
  }
});
