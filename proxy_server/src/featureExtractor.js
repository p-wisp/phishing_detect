

const fs = require("fs");
const path = require("path");
const net = require("net");
const cheerio = require("cheerio");
const { getDomain, getPublicSuffix, parse: tldParse } = require("tldts");

const WHITELIST_CSV = path.resolve(__dirname, "..", "whitelist", "whitelist.csv");


function toLowerKeyed(obj) {
  const out = {};
  if (!obj || typeof obj !== "object") return out;
  for (const [k, v] of Object.entries(obj)) out[String(k).toLowerCase()] = v;
  return out;
}

function safeArray(v) {
  if (Array.isArray(v)) return v;
  if (v === undefined || v === null) return [];
  return [v];
}

function shannonEntropy(s) {
  if (!s) return 0;
  const counts = new Map();
  for (const ch of String(s)) counts.set(ch, (counts.get(ch) || 0) + 1);
  const n = s.length;
  let H = 0;
  for (const c of counts.values()) {
    const p = c / n;
    H -= p * Math.log2(p);
  }
  return H;
}

// 단순 Levenshtein 거리 → [0,1] 유사도로 변환
function levenshteinSimilarity(a, b) {
  a = a || ""; b = b || "";
  const m = a.length, n = b.length;
  if (m === 0 && n === 0) return 1.0;
  // O(min(m,n)) 메모리 버전
  if (n > m) { const tmp = a; a = b; b = tmp; }
  const lenA = a.length, lenB = b.length;
  const prev = new Array(lenB + 1);
  for (let j = 0; j <= lenB; j++) prev[j] = j;
  for (let i = 1; i <= lenA; i++) {
    let prevDiag = prev[0];
    prev[0] = i;
    for (let j = 1; j <= lenB; j++) {
      const temp = prev[j];
      const cost = a.charCodeAt(i - 1) === b.charCodeAt(j - 1) ? 0 : 1;
      prev[j] = Math.min(prev[j] + 1, prev[j - 1] + 1, prevDiag + cost);
      prevDiag = temp;
    }
  }
  const dist = prev[lenB];
  const maxLen = Math.max(lenA, lenB);
  return maxLen ? (1 - dist / maxLen) : 1.0;
}

function hostnameFromHeader(reqHeaders) {
  const h = toLowerKeyed(reqHeaders);
  // 일반적으로 Host 헤더 사용
  let host = h["host"] || h[":authority"] || "";
  host = String(host || "").trim();
  // 일부 환경에서 포트가 포함될 수 있음, 제거
  if (host.includes(":")) host = host.split(":")[0];
  return host;
}


function etld1(host) {
  if (!host) return "";
  const d = getDomain(host);
  return d || host; 
}

function publicSuffix(host) {
  if (!host) return "";
  return getPublicSuffix(host) || "";
}

function subdomainDepth(host) {
  try {
    const info = tldParse(host);
    if (!info) return 0;
    const sub = info.subdomain || "";
    if (!sub) return 0;
    return sub.split(".").filter(Boolean).length;
  } catch { return 0; }
}

let WHITELIST = null;
function loadWhitelist() {
  if (WHITELIST) return WHITELIST;
  const set = new Set();
  try {
    const raw = fs.readFileSync(WHITELIST_CSV, "utf8");
    const lines = raw.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;
      // CSV 첫 컬럼만 사용
      const first = line.split(",")[0].trim();
      if (!first) continue;
      // 헤더 추정: 'domain' 포함 행 스킵
      if (i === 0 && /^\s*domain\b/i.test(first)) continue;
      const host = first.replace(/^https?:\/\//i, "");
      const d = etld1(host);
      if (d) set.add(d.toLowerCase());
    }
  } catch (e) {
  }
  WHITELIST = set;
  return WHITELIST;
}

// 응답 헤더 기반 피처
function responseHeaderFeatures(resHeaders) {
  const h = toLowerKeyed(resHeaders);
  const has_x_frame_options = h.hasOwnProperty("x-frame-options");
  const has_strict_transport_security = h.hasOwnProperty("strict-transport-security");
  const has_content_disposition_attachment = /attachment/i.test(String(h["content-disposition"] || ""));
  const has_x_xss_protection = h.hasOwnProperty("x-xss-protection");
  const has_content_security_policy = h.hasOwnProperty("content-security-policy");
  const has_x_content_type_options = h.hasOwnProperty("x-content-type-options");

  // Set-Cookie 보안 속성 검사 => 쿠키가 없으면 true, 있으면 모든 쿠키가 Secure+HttpOnly 여야 true
  let has_cookie_security = true;
  const setCookie = h["set-cookie"];
  const cookies = safeArray(setCookie);
  if (cookies.length > 0) {
    for (const c of cookies) {
      const s = String(c || "");
      const secure = /;\s*secure\b/i.test(s);
      const httpOnly = /;\s*httponly\b/i.test(s);
      if (!(secure && httpOnly)) { has_cookie_security = false; break; }
    }
  }

  return {
    has_x_frame_options,
    has_strict_transport_security,
    has_content_disposition_attachment,
    has_x_xss_protection,
    has_content_security_policy,
    has_x_content_type_options,
    has_cookie_security,
  };
}

// 요청 헤더 기반 피처
function requestHeaderFeatures(reqHeaders, initialHostEtld1) {
  const wl = loadWhitelist();
  const inWL = wl.has(initialHostEtld1.toLowerCase());
  return { req_initial_host_in_whitelist: inWL };
}

// 혼합 기반 피처
function mixedHeaderFeatures(redirectChainHosts) {
  const wl = loadWhitelist();
  const chainHosts = Array.isArray(redirectChainHosts) ? redirectChainHosts : [];
  const firstHost = chainHosts[0] || "";
  const lastHost = chainHosts[chainHosts.length - 1] || firstHost || "";

  const firstEtld1 = etld1(firstHost).toLowerCase();
  const lastEtld1 = etld1(lastHost).toLowerCase();

  // 리다이렉션 판정: eTLD+1이 바뀐 경우만 (http→https 업그레이드, www 추가 등은 제외)
  const isRedirect = !!(firstEtld1 && lastEtld1 && firstEtld1 !== lastEtld1);

  // 레벨 결정
  const firstWL = firstEtld1 ? loadWhitelist().has(firstEtld1) : false;
  const lastWL = lastEtld1 ? loadWhitelist().has(lastEtld1) : false;
  let mixed_redirection_level = "level0";
  if (isRedirect) {
    if (firstWL && !lastWL) mixed_redirection_level = "level1";
    else if (!firstWL && !lastWL) mixed_redirection_level = "level2";
    else if (!firstWL && lastWL) mixed_redirection_level = "level3";
    else mixed_redirection_level = "level0"; 
  }

  //홉 수: 체인에서 eTLD+1 값이 변경된 횟수만 카운트
  let mixed_redirection_hop_count = 0;
  if (chainHosts.length >= 2) {
    let prev = etld1(chainHosts[0]).toLowerCase();
    for (let i = 1; i < chainHosts.length; i++) {
      const cur = etld1(chainHosts[i]).toLowerCase();
      if (cur && prev && cur !== prev) mixed_redirection_hop_count++;
      prev = cur || prev;
    }
  }

  // 호스트 유사도
  const mixed_host_similarity = isRedirect ? levenshteinSimilarity(firstHost, lastHost) : 1.0;

  return { mixed_redirection_level, mixed_redirection_hop_count, mixed_host_similarity };
}

// DOM 기반 피처
function domFeatures(domHtml, pageHostForLinks) {
  if (!domHtml || typeof domHtml !== "string" || !domHtml.trim()) {
    return {
      dom_total_nodes: 0,
      dom_max_depth: 0,
      dom_num_forms: 0,
      dom_num_password_fields: 0,
      dom_form_action_suspicious: false,
      dom_num_iframes: 0,
      dom_has_js_redirect: false,
      dom_percent_external_links: 0,
      dom_num_hidden_elements: 0,
    };
  }

  const $ = cheerio.load(domHtml);

  //전체 노드 수
  const allNodes = $('*');
  const dom_total_nodes = allNodes.length;

  // 최대 깊이 (조상 수를 이용; cheerio는 루트까지 parents() 제공)
  let dom_max_depth = 0;
  allNodes.each((_, el) => {
    const depth = $(el).parents().length;
    if (depth > dom_max_depth) dom_max_depth = depth;
  });

  // 폼 수
  const forms = $('form');
  const dom_num_forms = forms.length;

  // 패스워드 필드 수
  const dom_num_password_fields = $('input[type="password"]').length;

  // form action 의심 여부 
  let dom_form_action_suspicious = false;
  forms.each((_, f) => {
    const action = String($(f).attr('action') || "").trim().toLowerCase();
    if (!action || action === '#' || action.startsWith('javascript:')) {
      dom_form_action_suspicious = true;
      return false; 
    }
  });

  const dom_num_iframes = $('iframe').length;

  let dom_has_js_redirect = false;
  if ($('meta[http-equiv]')
        .filter((_, m) => /refresh/i.test(String($(m).attr('http-equiv') || '')))
        .length > 0) {
    dom_has_js_redirect = true;
  } else {
    $('script').each((_, s) => {
      const txt = $(s).html() || "";
      if (/\b(window|document)\.location\b/i.test(txt) || /\blocation\s*\./i.test(txt)) {
        dom_has_js_redirect = true;
        return false; 
      }
    });
  }

  //외부 링크 비율 
  let dom_percent_external_links = 0;
  const pageDomain = etld1(pageHostForLinks);
  const anchors = $('a[href]');
  if (anchors.length > 0 && pageDomain) {
    let external = 0, total = 0;
    anchors.each((_, a) => {
      const hrefRaw = String($(a).attr('href') || "").trim();
      if (!hrefRaw) return;
      // 절대 URL만 평가 
      if (/^https?:\/\//i.test(hrefRaw) || hrefRaw.startsWith("//")) {
        let href = hrefRaw;
        if (href.startsWith("//")) href = "http:" + href; 
        try {
          const u = new URL(href);
          const d = etld1(u.hostname.toLowerCase());
          if (d && d !== pageDomain.toLowerCase()) external++;
          total++;
        } catch { /* 무시 */ }
      } else {
        total++;
      }
    });
    dom_percent_external_links = total > 0 ? (external / total) * 100 : 0;
  }

  //숨김요소
  let dom_num_hidden_elements = 0;
  allNodes.each((_, el) => {
    const style = String($(el).attr('style') || '').toLowerCase();
    if (/display\s*:\s*none/.test(style)) dom_num_hidden_elements++;
  });
  dom_num_hidden_elements += $('input[type="hidden"]').length;
  dom_num_hidden_elements += $('[hidden]').length;

  return {
    dom_total_nodes,
    dom_max_depth,
    dom_num_forms,
    dom_num_password_fields,
    dom_form_action_suspicious,
    dom_num_iframes,
    dom_has_js_redirect,
    dom_percent_external_links,
    dom_num_hidden_elements,
  };
}

function urlFeaturesFromRequest(reqHeaders) {
  const host = hostnameFromHeader(reqHeaders).toLowerCase();

  const url_hostname_length = host.length;
  const url_subdomain_depth = subdomainDepth(host);
  const url_has_ip_address = net.isIP(host) !== 0; // 0이면 IP 아님
  const url_num_special_chars = (host.replace(/[a-z0-9.]/gi, "")).length; // 영숫자와 점 제외
  const url_tld = publicSuffix(host);
  const url_domain_entropy = shannonEntropy(etld1(host));

  return {
    url_hostname_length,
    url_subdomain_depth,
    url_has_ip_address,
    url_num_special_chars,
    url_tld,
    url_domain_entropy,
  };
}


async function extract(reqHeaders = {}, resHeaders = {}, redirectChainHosts = [], domHtml) {
  try {
    const resPart = responseHeaderFeatures(resHeaders);

    const initialHost = (Array.isArray(redirectChainHosts) && redirectChainHosts.length > 0)
      ? String(redirectChainHosts[0] || "")
      : hostnameFromHeader(reqHeaders);
    const initialEtld1 = etld1(initialHost).toLowerCase();

    const reqPart = requestHeaderFeatures(reqHeaders, initialEtld1);
    const mixPart = mixedHeaderFeatures(redirectChainHosts && redirectChainHosts.length ? redirectChainHosts : [initialHost]);
    const domPart = domFeatures(domHtml, (redirectChainHosts && redirectChainHosts.length) ? redirectChainHosts[redirectChainHosts.length - 1] : initialHost);
    const urlPart = urlFeaturesFromRequest(reqHeaders);

    return {
      // 응답 헤더 
      has_x_frame_options: resPart.has_x_frame_options,
      has_strict_transport_security: resPart.has_strict_transport_security,
      has_content_disposition_attachment: resPart.has_content_disposition_attachment,
      has_x_xss_protection: resPart.has_x_xss_protection,
      has_content_security_policy: resPart.has_content_security_policy,
      has_x_content_type_options: resPart.has_x_content_type_options,
      has_cookie_security: resPart.has_cookie_security,

      // 요청 헤더 
      req_initial_host_in_whitelist: reqPart.req_initial_host_in_whitelist,

      // 혼합 
      mixed_redirection_level: mixPart.mixed_redirection_level,
      mixed_redirection_hop_count: mixPart.mixed_redirection_hop_count,
      mixed_host_similarity: mixPart.mixed_host_similarity,

      // DOM 
      dom_total_nodes: domPart.dom_total_nodes,
      dom_max_depth: domPart.dom_max_depth,
      dom_num_forms: domPart.dom_num_forms,
      dom_num_password_fields: domPart.dom_num_password_fields,
      dom_form_action_suspicious: domPart.dom_form_action_suspicious,
      dom_num_iframes: domPart.dom_num_iframes,
      dom_has_js_redirect: domPart.dom_has_js_redirect,
      dom_percent_external_links: domPart.dom_percent_external_links,
      dom_num_hidden_elements: domPart.dom_num_hidden_elements,

      // URL 
      url_hostname_length: urlPart.url_hostname_length,
      url_subdomain_depth: urlPart.url_subdomain_depth,
      url_has_ip_address: urlPart.url_has_ip_address,
      url_num_special_chars: urlPart.url_num_special_chars,
      url_tld: urlPart.url_tld,
      url_domain_entropy: urlPart.url_domain_entropy
    };
  } catch (e) {
    //오류시 기본값
    return {
      has_x_frame_options: false,
      has_strict_transport_security: false,
      has_content_disposition_attachment: false,
      has_x_xss_protection: false,
      has_content_security_policy: false,
      has_x_content_type_options: false,
      has_cookie_security: true,
      req_initial_host_in_whitelist: false,
      mixed_redirection_level: "level0",
      mixed_redirection_hop_count: 0,
      mixed_host_similarity: 1.0,
      dom_total_nodes: 0,
      dom_max_depth: 0,
      dom_num_forms: 0,
      dom_num_password_fields: 0,
      dom_form_action_suspicious: false,
      dom_num_iframes: 0,
      dom_has_js_redirect: false,
      dom_percent_external_links: 0,
      dom_num_hidden_elements: 0,
      url_hostname_length: 0,
      url_subdomain_depth: 0,
      url_has_ip_address: false,
      url_num_special_chars: 0,
      url_tld: "",
      url_domain_entropy: 0
    };
  }
}

module.exports = { extract };
