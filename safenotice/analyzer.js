/**
 * SafeNotice Enhanced Analyzer: Original vs Fake Identifier
 */

const INSTITUTION_REGISTRY = [
  {
    name: "Anna University",
    keywords: ["anna univ", "anna university", "coe1", "au coe"],
    officialDomain: "annauniv.edu",
    officialPortal: "https://www.annauniv.edu"
  },
  {
    name: "IIT Madras",
    keywords: ["iit madras", "iitm"],
    officialDomain: "iitm.ac.in",
    officialPortal: "https://www.iitm.ac.in"
  },
  {
    name: "NIT Trichy",
    keywords: ["nit trichy", "nitt"],
    officialDomain: "nitt.edu",
    officialPortal: "https://www.nitt.edu"
  },
  {
    name: "Directorate of Technical Education (DoTE)",
    keywords: ["dote", "tndte", "diploma exam"],
    officialDomain: "tndte.gov.in",
    officialPortal: "https://dte.tn.gov.in"
  },
  {
    name: "UGC / AICTE",
    keywords: ["aicte", "ugc", "scholarship portal"],
    officialDomain: "aicte-india.org",
    officialPortal: "https://www.aicte-india.org"
  }
];

const KNOWN_SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'cutt.ly', 'rb.gy'];
const PAYMENT_TRAPS = ['fee', 'pay', 'upi', 'arrear', 'registration charge', 'qr', 'gpay'];

function isRawIP(hostname) {
  return /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(hostname);
}

function analyzeLink(rawUrl, linkText = '', customOfficialDomains = []) {
  const result = {
    url: rawUrl,
    domain: '',
    status: 'unknown',    // 'verified' | 'suspicious' | 'unknown'
    verdict: 'UNVERIFIED_EXTERNAL', // 'ORIGINAL_VERIFIED' | 'FAKE_IMPOSTOR' | 'UNVERIFIED_EXTERNAL'
    riskLevel: 'low',
    claimedInstitution: null,
    realOriginalUrl: null,
    proofOfFake: [],
    reasons: [],
    recommendedAction: 'Check before you click.'
  };

  if (!rawUrl || typeof rawUrl !== 'string') {
    result.status = 'suspicious';
    result.verdict = 'FAKE_IMPOSTOR';
    result.riskLevel = 'medium';
    result.proofOfFake.push('Empty or invalid link reference.');
    return result;
  }

  let parsed;
  try {
    parsed = new URL(rawUrl, window?.location?.href || 'https://unknown.local');
    result.domain = parsed.hostname.toLowerCase();
  } catch {
    result.status = 'suspicious';
    result.verdict = 'FAKE_IMPOSTOR';
    result.proofOfFake.push('Malformed or deceptive URL structure.');
    return result;
  }

  const cleanText = (linkText || '').toLowerCase();
  const lowerUrl = parsed.href.toLowerCase();
  const host = result.domain;

  // 1. Check if the link claims an institution
  let matchedInstitution = null;
  for (const inst of INSTITUTION_REGISTRY) {
    const claimsInst = inst.keywords.some(kw => cleanText.includes(kw) || host.includes(kw.replace(/\s+/g, '')));
    if (claimsInst) {
      matchedInstitution = inst;
      break;
    }
  }

  if (matchedInstitution) {
    result.claimedInstitution = matchedInstitution.name;
    result.realOriginalUrl = matchedInstitution.officialPortal;

    const isGenuineHost = host === matchedInstitution.officialDomain || host.endsWith('.' + matchedInstitution.officialDomain);

    if (isGenuineHost) {
      result.status = 'verified';
      result.verdict = 'ORIGINAL_VERIFIED';
      result.riskLevel = 'low';
      result.reasons.push(`Authentic domain registered to ${matchedInstitution.name}.`);
      result.recommendedAction = `Authentic circular on official ${matchedInstitution.name} portal.`;
      return result;
    } else {
      result.status = 'suspicious';
      result.verdict = 'FAKE_IMPOSTOR';
      result.riskLevel = 'high';
      result.proofOfFake.push(`Claims to be "${matchedInstitution.name}", but destination is: ${host}`);
      result.proofOfFake.push(`Official registered domain must end in: ${matchedInstitution.officialDomain}`);
      result.reasons = [...result.proofOfFake];
      result.recommendedAction = `Do NOT pay or click. Go directly to official portal: ${matchedInstitution.officialPortal}`;
      return result;
    }
  }

  // 2. Custom official whitelist check
  const isCustomOfficial = (customOfficialDomains || []).some(d => host === d.toLowerCase() || host.endsWith('.' + d.toLowerCase()));
  if (isCustomOfficial) {
    result.status = 'verified';
    result.verdict = 'ORIGINAL_VERIFIED';
    result.riskLevel = 'low';
    result.reasons.push('Domain matches your configured college whitelist.');
    result.recommendedAction = 'Safe to navigate.';
    return result;
  }

  // 3. Raw IP check
  if (isRawIP(host)) {
    result.status = 'suspicious';
    result.verdict = 'FAKE_IMPOSTOR';
    result.riskLevel = 'high';
    result.proofOfFake.push('Uses a bare IP address instead of a recognized college domain.');
    result.reasons = [...result.proofOfFake];
    result.recommendedAction = 'Never submit login credentials or fees to raw IP addresses.';
    return result;
  }

  // 4. URL shorteners
  if (KNOWN_SHORTENERS.includes(host)) {
    result.status = 'suspicious';
    result.verdict = 'FAKE_IMPOSTOR';
    result.riskLevel = 'medium';
    result.proofOfFake.push('Masked with a URL shortener to hide the real destination.');
    result.reasons = [...result.proofOfFake];
    result.recommendedAction = 'Do not open shortened links claiming to be official college notices.';
    return result;
  }

  // 5. Payment / Fee traps
  const hasPaymentPrompt = PAYMENT_TRAPS.some(p => cleanText.includes(p) || lowerUrl.includes(p));
  const hasUrgency = cleanText.includes('urgent') || cleanText.includes('pay now') || cleanText.includes('otp') || cleanText.includes('blocked');

  if (hasPaymentPrompt && (hasUrgency || host.includes('fee') || host.includes('exam'))) {
    result.status = 'suspicious';
    result.verdict = 'FAKE_IMPOSTOR';
    result.riskLevel = 'high';
    result.proofOfFake.push('Unverified external site demanding fee payments or OTP.');
    result.proofOfFake.push('Legitimate colleges in India only accept fees through official banks (.ac.in / .edu.in or SBI Collect).');
    result.reasons = [...result.proofOfFake];
    result.recommendedAction = 'Verify this notice directly with your college department before paying.';
    return result;
  }

  // 6. Default unknown external
  result.status = 'unknown';
  result.verdict = 'UNVERIFIED_EXTERNAL';
  result.riskLevel = 'low';
  result.reasons.push('External third-party link. Not listed in official college directory.');
  result.recommendedAction = 'Proceed with normal caution if you recognize this domain.';
  return result;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { analyzeLink, INSTITUTION_REGISTRY };
}
