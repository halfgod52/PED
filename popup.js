// Tab switching
document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => {
      t.classList.remove("active");
      t.setAttribute("aria-selected", "false");
    });
    document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
    tab.classList.add("active");
    tab.setAttribute("aria-selected", "true");
    document.getElementById("tab-" + tab.dataset.tab).classList.add("active");
  });
});

function loadHistory() {
  chrome.storage.local.get({ scanHistory: [] }, data => {
    const list = document.getElementById("history-list");
    if (!list) return;
    list.innerHTML = "";
    if (data.scanHistory.length === 0) {
      list.innerHTML = '<li class="history-empty">No recent scans</li>';
      return;
    }
    data.scanHistory.forEach(item => {
      const li = document.createElement("li");
      li.className = "history-item " + item.level;
      
      const time = new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      li.innerHTML = `
        <div class="hist-time">${time}</div>
        <div class="hist-subj" title="${esc(item.subject)}">${esc(item.subject)}</div>
        <div class="hist-level">${item.level === 'safe' ? 'Safe' : item.level === 'suspicious' ? 'Suspicious' : 'Phishing'}</div>
      `;
      list.appendChild(li);
    });
  });
}

function saveHistory(subject, level) {
  if (!subject) return;
  chrome.storage.local.get({ scanHistory: [] }, data => {
    let hist = data.scanHistory;
    hist.unshift({ timestamp: Date.now(), subject, level });
    hist = hist.slice(0, 5);
    chrome.storage.local.set({ scanHistory: hist }, loadHistory);
  });
}

document.addEventListener("DOMContentLoaded", () => {
  loadHistory();
});

function getActiveTab(cb) {
  chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
    const tab = tabs[0];
    cb((!tab || !tab.url || !tab.url.includes("mail.google.com")) ? null : tab);
  });
}

function sendMessageWithTimeout(tabId, message, timeoutMs, cb) {
  let responded = false;
  const timer = setTimeout(() => {
    if (!responded) {
      responded = true;
      cb(null, true); // pass true to indicate timeout
    }
  }, timeoutMs);

  chrome.tabs.sendMessage(tabId, message, response => {
    if (!responded) {
      responded = true;
      clearTimeout(timer);
      cb(chrome.runtime.lastError ? null : response, false);
    }
  });
}

function esc(s) {
  return s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

// Wraps domain-looking substrings in a monospace span so raw technical
// evidence (a flagged domain, an email address) visually stands apart
// from the app's own explanatory sentence around it.
function highlightDomains(s) {
  return esc(s).replace(/([a-z0-9-]+\.)+[a-z]{2,}/gi, m => `<span class="mono">${m}</span>`);
}

const GROUP_META = {
  sender:      { icon: "🧑", label: "Sender" },
  links:       { icon: "🔗", label: "Links" },
  content:     { icon: "📝", label: "Content" },
  attachments: { icon: "📎", label: "Attachments" },
};

// Renders the scan result's flags as three labeled sections instead of one
// flat bullet list — makes it clear at a glance *where* each signal came
// from (who sent it, where its links go, what it says).
function renderFlagGroups(groups) {
  const container = document.getElementById("flags-groups");
  container.innerHTML = "";
  for (const key of ["sender", "links", "content", "attachments"]) {
    const items = groups[key];
    if (!items || !items.length) continue;
    const meta = GROUP_META[key];
    const li = items.map(f => `<li>${highlightDomains(f)}</li>`).join("");
    const section = document.createElement("div");
    section.className = "flag-group";
    section.innerHTML = `<div class="flag-group-title">${meta.icon} ${meta.label}</div><ul>${li}</ul>`;
    container.appendChild(section);
  }
}

function setRiskMeter(level) {
  const meter = document.getElementById("risk-meter");
  meter.classList.remove("hidden");
  meter.querySelectorAll(".risk-seg").forEach(seg => {
    seg.classList.toggle("active", seg.dataset.level === level);
  });
}

// ── SCAN SINGLE EMAIL ──────────────────────────────────────────────────
document.getElementById("scanBtn").addEventListener("click", () => {
  const resultBox   = document.getElementById("result-box");
  const resultLabel = document.getElementById("result-label");
  const resultScore = document.getElementById("result-score");
  const riskMeter   = document.getElementById("risk-meter");
  const scanIcon    = document.getElementById("scanIcon");
  const flagsGroups = document.getElementById("flags-groups");

  resultBox.className = "result-box scanning";
  resultLabel.textContent = "Scanning…";
  resultScore.textContent = "";
  riskMeter.classList.add("hidden");
  flagsGroups.innerHTML = "";
  scanIcon.classList.add("spinning");

  getActiveTab(tab => {
    if (!tab) {
      scanIcon.classList.remove("spinning");
      resultBox.className = "result-box error";
      resultLabel.textContent = "Open a Gmail email first";
      return;
    }
    sendMessageWithTimeout(tab.id, { action: "scan" }, 8000, (response, timedOut) => {
      scanIcon.classList.remove("spinning");
      if (timedOut) {
        resultBox.className = "result-box error";
        resultLabel.textContent = "No response from Gmail tab — try reloading";
        return;
      }
      if (!response) {
        resultBox.className = "result-box error";
        resultLabel.textContent = "Reload Gmail tab and retry";
        return;
      }
      resultBox.className = "result-box " + response.level;
      resultLabel.textContent = response.result;

      const domWarning = document.getElementById("dom-warning");
      if (response.domFailures) {
        domWarning.textContent = "⚠️ Couldn't read: " + response.domFailures.join(", ");
        domWarning.classList.remove("hidden");
      } else {
        domWarning.classList.add("hidden");
      }

      if (response.level === "unknown") {
        // Nothing was actually analyzed — showing Safe/Suspicious/Phishing
        // or a score here would look like a real verdict when it isn't one.
        riskMeter.classList.add("hidden");
        resultScore.textContent = "";
        renderFlagGroups({});
        document.getElementById("allowlist-container").classList.add("hidden");
        return;
      }

      resultScore.innerHTML = `Score: ${response.score} / 81 <span class="score-help tooltip-trigger">?<span class="tooltip">0 = Safe | 1-3 = Suspicious | 4+ = Phishing. Max possible score is 81.</span></span>`;
      setRiskMeter(response.level);
      renderFlagGroups(response.groups || {});
      saveHistory(response.subject, response.level);

      const allowlistContainer = document.getElementById("allowlist-container");
      const allowlistBtn = document.getElementById("allowlistBtn");
      if (response.level !== "safe" && response.senderEmail) {
        allowlistContainer.classList.remove("hidden");
        allowlistBtn.onclick = () => {
          chrome.storage.sync.get({ trustedSenders: [] }, data => {
            const list = data.trustedSenders;
            const email = response.senderEmail.toLowerCase();
            if (!list.includes(email)) {
              list.push(email);
              chrome.storage.sync.set({ trustedSenders: list }, () => {
                document.getElementById("scanBtn").click();
              });
            }
          });
        };
      } else {
        allowlistContainer.classList.add("hidden");
      }
    });
  });
});

// ── SCAN INBOX ─────────────────────────────────────────────────────────
document.getElementById("inboxBtn").addEventListener("click", () => {
  const inboxResult  = document.getElementById("inbox-result");
  const inboxSummary = document.getElementById("inbox-summary");
  inboxResult.innerHTML = '<div class="inbox-status scanning">Scanning inbox (this may take a moment)…</div>';
  inboxSummary.classList.add("hidden");

  getActiveTab(tab => {
    if (!tab) {
      inboxResult.innerHTML = '<div class="inbox-status error">Go to Gmail inbox first</div>';
      return;
    }

    sendMessageWithTimeout(tab.id, { action: "scanInbox" }, 30000, (response, timedOut) => {
      if (timedOut) {
        inboxResult.innerHTML = '<div class="inbox-status error">No response from Gmail tab — try reloading</div>';
        return;
      }
      if (!response) {
        inboxResult.innerHTML = '<div class="inbox-status error">Reload Gmail and retry</div>';
        return;
      }

      const { emails, totalScanned, domFailures } = response;

      if (typeof totalScanned === "number") {
        inboxSummary.classList.remove("hidden");
        const noun = totalScanned === 1 ? "email" : "emails";
        let summaryText = `<span>${totalScanned} ${noun} scanned</span><span class="mono">${emails.length} flagged</span>`;
        if (domFailures) {
          summaryText += ` <span style="color:#f59e0b;" title="Missing: ${domFailures.join(', ')}">⚠️</span>`;
        }
        inboxSummary.innerHTML = summaryText;
      }

      if (!emails.length) {
        inboxResult.innerHTML = '<div class="inbox-status clean">✅ No threats in visible emails</div>';
        return;
      }

      const phishing  = emails.filter(e => e.level === "phishing");
      const suspicious = emails.filter(e => e.level === "suspicious");

      let html = "";
      if (phishing.length)
        html += `<div class="inbox-section-label phishing-label">🚨 Likely Phishing (${phishing.length})</div>`
              + phishing.map(emailCard).join("");
      if (suspicious.length)
        html += `<div class="inbox-section-label suspicious-label">⚠️ Suspicious (${suspicious.length})</div>`
              + suspicious.map(emailCard).join("");

      inboxResult.innerHTML = html;

      // ── Click a card → tell content script to click that Gmail row ──
      inboxResult.querySelectorAll(".email-card").forEach(card => {
        card.addEventListener("click", () => {
          const threadId = card.dataset.threadId;

          // Visual feedback
          card.classList.add("opening");
          card.querySelector(".card-arrow").textContent = "…";

          chrome.tabs.sendMessage(tab.id, { action: "openThread", threadId }, res => {
            if (chrome.runtime.lastError || !res || !res.ok) {
              card.classList.remove("opening");
              card.querySelector(".card-arrow").textContent = "→";
              card.querySelector(".email-subject").textContent += " (couldn't open — scroll email into view)";
            } else {
              window.close(); // Close popup; Gmail handles the navigation
            }
          });
        });
      });
    });
  });
});

function emailCard(e) {
  const chips = e.flags.map(f => `<span class="flag-chip">${esc(f)}</span>`).join("");
  return `
    <div class="email-card ${e.level}" data-thread-id="${esc(e.threadId)}">
      <div class="card-top">
        <div class="card-text">
          <div class="email-sender">${esc(e.sender)}</div>
          <div class="email-subject">${esc(e.subject)}</div>
        </div>
        <span class="card-arrow">→</span>
      </div>
      <div class="email-flags">${chips}</div>
    </div>`;
}
