/**
 * SafeNotice Content Script
 */

(function () {
  if (window.hasSafeNoticeInitialized) return;
  window.hasSafeNoticeInitialized = true;

  let officialDomains = [];
  let scanningEnabled = true;

  const scannedUrls = new Set();
  const summaryCounts = { verified: 0, unknown: 0, suspicious: 0 };

  async function loadConfig() {
    const data = await chrome.storage.local.get(['officialDomains', 'scanningEnabled']);
    officialDomains = data.officialDomains || [];
    scanningEnabled = data.scanningEnabled !== false;
  }

  function escapeHTML(str) {
    return String(str || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function getOrCreateModal() {
    let modal = document.getElementById('safenotice-advisory-modal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'safenotice-advisory-modal';
      modal.style.cssText = `
        position: fixed;
        bottom: 24px;
        right: 24px;
        width: 380px;
        max-width: 90vw;
        background: #ffffff;
        border-radius: 12px;
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2), 0 1px 3px rgba(0,0,0,0.1);
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        z-index: 2147483647;
        padding: 18px;
        border: 1px solid #e2e8f0;
        display: none;
        box-sizing: border-box;
        color: #1e293b;
      `;
      document.body.appendChild(modal);
    }
    return modal;
  }

  function showAdvisoryModal(analysis) {
    const modal = getOrCreateModal();
    const isOriginal = analysis.status === 'verified';
    const isFake = analysis.status === 'suspicious';

    const headerColor = isOriginal ? '#10b981' : isFake ? '#ef4444' : '#f59e0b';
    const headerTitle = isOriginal ? '✓ GENUINE OFFICIAL LINK' : isFake ? '🛑 FAKE / IMPOSTOR DETECTED' : '⚠️ UNVERIFIED EXTERNAL LINK';

    modal.innerHTML = `
      <div style="border-bottom: 2px solid ${headerColor}; padding-bottom: 8px; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center;">
        <strong style="color: ${headerColor}; font-size: 14px;">${headerTitle}</strong>
        <button id="safenotice-modal-close" style="background:none; border:none; font-size:20px; cursor:pointer; color:#64748b; line-height:1;">&times;</button>
      </div>

      ${(analysis.proofOfFake && analysis.proofOfFake.length) ? `
        <div style="background: #fef2f2; border: 1px solid #fee2e2; border-radius: 8px; padding: 10px; margin-bottom: 12px;">
          <div style="font-size: 11px; color: #991b1b; font-weight: 700; margin-bottom: 4px;">WHY IT IS FAKE:</div>
          <ul style="margin: 0; padding-left: 18px; color: #b91c1c; font-size: 12px;">
            ${analysis.proofOfFake.map(p => `<li style="margin-bottom: 3px;">${escapeHTML(p)}</li>`).join('')}
          </ul>
        </div>
      ` : ''}

      ${analysis.realOriginalUrl ? `
        <div style="background: #f0fdf4; border: 1px solid #dcfce7; border-radius: 8px; padding: 10px; margin-bottom: 12px;">
          <div style="font-size: 11px; color: #166534; font-weight: 700;">AUTHENTIC ORIGINAL SITE:</div>
          <div style="font-size: 12px; color: #15803d; word-break: break-all; margin: 4px 0 8px 0;">
            ${escapeHTML(analysis.realOriginalUrl)}
          </div>
          <a href="${escapeHTML(analysis.realOriginalUrl)}" target="_blank" rel="noopener noreferrer" 
             style="display: inline-block; background: #16a34a; color: white; text-decoration: none; font-size: 11px; font-weight: bold; padding: 6px 12px; border-radius: 6px;">
            Go to Real Official Website &rarr;
          </a>
        </div>
      ` : ''}

      <div style="font-size: 11px; color: #475569; margin-bottom: 12px; background: #f8fafc; padding: 8px; border-radius: 6px;">
        <strong>Scanned Link Destination:</strong><br>
        <code style="word-break: break-all; color: #0f172a;">${escapeHTML(analysis.url)}</code>
      </div>

      <div style="background: #fffbeb; border: 1px solid #fef3c7; padding: 8px 10px; border-radius: 6px; font-size: 12px; color: #92400e; margin-bottom: 12px;">
        <strong>Advisory:</strong> ${escapeHTML(analysis.recommendedAction)}
      </div>

      <div style="display: flex; gap: 8px;">
        <a href="https://cybercrime.gov.in/" target="_blank" rel="noopener noreferrer" style="flex:1; text-align:center; background: #f1f5f9; color: #334155; text-decoration:none; font-size:12px; font-weight:600; padding: 7px 10px; border-radius: 6px;">Report Scam</a>
        <button id="safenotice-modal-dismiss" style="flex:1; background: #2563eb; color: #ffffff; border:none; font-size:12px; font-weight:600; padding: 7px 10px; border-radius: 6px; cursor:pointer;">I Understand</button>
      </div>
    `;

    modal.style.display = 'block';
    modal.querySelector('#safenotice-modal-close').onclick = () => modal.style.display = 'none';
    modal.querySelector('#safenotice-modal-dismiss').onclick = () => modal.style.display = 'none';
  }

  function attachBadge(linkElement, analysis) {
    if (linkElement.dataset.safenoticeAttached === 'true') return;
    linkElement.dataset.safenoticeAttached = 'true';

    const badge = document.createElement('span');
    badge.className = 'safenotice-badge';

    const color = analysis.status === 'verified' ? '#10b981' : analysis.status === 'suspicious' ? '#ef4444' : '#f59e0b';
    const symbol = analysis.status === 'verified' ? '✓' : analysis.status === 'suspicious' ? '!' : '?';

    badge.style.cssText = `
      display: inline-flex !important;
      align-items: center !important;
      justify-content: center !important;
      width: 16px !important;
      height: 16px !important;
      margin-left: 6px !important;
      font-size: 11px !important;
      font-weight: bold !important;
      color: #ffffff !important;
      background-color: ${color} !important;
      border-radius: 50% !important;
      cursor: pointer !important;
      vertical-align: middle !important;
      box-shadow: 0 1px 3px rgba(0,0,0,0.2) !important;
      user-select: none !important;
      text-decoration: none !important;
      line-height: 1 !important;
    `;
    badge.title = `SafeNotice: ${(analysis.status || 'unknown').toUpperCase()} - Click for details`;
    badge.innerText = symbol;

    badge.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      showAdvisoryModal(analysis);
    });

    if (linkElement.nextSibling) {
      linkElement.parentNode.insertBefore(badge, linkElement.nextSibling);
    } else {
      linkElement.parentNode.appendChild(badge);
    }
  }

  function scanPageLinks() {
    if (!scanningEnabled) return;

    const links = document.querySelectorAll('a[href]');
    links.forEach(link => {
      const rawHref = link.getAttribute('href');
      if (!rawHref || rawHref.startsWith('#') || rawHref.startsWith('javascript:')) return;

      let absoluteUrl;
      try {
        absoluteUrl = new URL(rawHref, window.location.href).href;
      } catch (e) {
        return;
      }

      const text = link.innerText || link.getAttribute('title') || '';
      const analysis = analyzeLink(absoluteUrl, text, officialDomains);

      if (!scannedUrls.has(absoluteUrl)) {
        scannedUrls.add(absoluteUrl);
        if (analysis.status === 'verified') summaryCounts.verified++;
        else if (analysis.status === 'suspicious') summaryCounts.suspicious++;
        else summaryCounts.unknown++;
      }

      attachBadge(link, analysis);
    });

    try {
      chrome.runtime.sendMessage({
        action: 'UPDATE_SUMMARY_COUNTS',
        counts: summaryCounts,
        hostname: window.location.hostname
      });
    } catch (ignore) {}
  }

  function initObserver() {
    const observer = new MutationObserver(mutations => {
      let shouldRescan = false;
      for (const m of mutations) {
        if (m.addedNodes.length > 0) {
          shouldRescan = true;
          break;
        }
      }
      if (shouldRescan) scanPageLinks();
    });

    observer.observe(document.body, { childList: true, subtree: true });
  }

  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.action === 'TRIGGER_PAGE_SCAN') {
      scanPageLinks();
      sendResponse({ status: 'completed', counts: summaryCounts });
    } else if (msg.action === 'SHOW_INSPECT_MODAL') {
      showAdvisoryModal(msg.analysis);
    }
  });

  loadConfig().then(() => {
    scanPageLinks();
    initObserver();
  });
})();
