const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const zlib = require("zlib");
const { setTimeout: delay } = require("timers/promises");
const forge = require("node-forge");
let puppeteer = null; 
try { puppeteer = require("puppeteer"); } catch (_) {
  console.warn("[puppeteer] module not installed. Run: npm i puppeteer");
}
const { Proxy } = require("http-mitm-proxy");//중간자 조작하는 모듈

const PORT = 7777;
const SSL_CA_DIR = path.resolve(__dirname, "..", "ca-store");//개인키, ca인증서(브라우저 등록용)가 있는 디렋터리
const BLOCK_HTML = fs.readFileSync(path.resolve(__dirname, "..", "views", "block.html"));

const WHITELIST_PATH = path.resolve(__dirname, "..", "whitelist", "whitelist.csv");
let whitelistDomains = [];

function loadWhitelist() {
  try {
    const raw = fs.readFileSync(WHITELIST_PATH, "utf8");
    const lines = raw.replace(/^\uFEFF/, "").split(/\r?\n/);
    const items = [];
    for (const line of lines) {
      const noComment = line.split('#')[0];
      if (!noComment.trim()) continue;
      for (const cell of noComment.split(',')) {
        const d = cell.trim().toLowerCase();
        if (d) items.push(d);
      }
    }
    whitelistDomains = Array.from(new Set(items));
    console.log(`[whitelist] loaded ${whitelistDomains.length} entries`);
  } catch (e) {
    console.warn(`[whitelist] cannot read ${WHITELIST_PATH}:`, e.message);
    whitelistDomains = [];
  }
}
function hostMatchesWhitelist(hostname) {
  const h = String(hostname || '').toLowerCase();
  if (!h) return false;
  for (const d of whitelistDomains) {
    if (!d) continue;
    // match rules: exact, subdomain suffix, or simple include (per user request)
    if (h === d) return true;
    if (h.endsWith('.' + d)) return true;
    if (h.includes(d)) return true; // NOTE: broad match; consider removing if too permissive
  }
  return false;
}
loadWhitelist();
try {
  fs.watch(WHITELIST_PATH, { persistent: false }, () => {
    try { loadWhitelist(); } catch (_) {}
  });
} catch (_) { }

let renderSetting = 1; 
const REDIRECT_CHAIN_TTL_MS = 5 * 60 * 1000; // 5분 동안 보관
const redirectChains = new Map(); 

function getRequestUrl(ctx) {
  const req = ctx.clientToProxyRequest;
  const host = req?.headers?.host || "";
  const scheme = ctx.isSSL ? "https" : "http";
  const pathPart = req?.url || "/";
  const slash = pathPart.startsWith("/") ? "" : "/";
  return `${scheme}://${host}${slash}${pathPart}`;
}
function ensureAbsUrl(loc, baseUrl) {
  try { return new URL(loc, baseUrl).href; } catch { return null; }
}
function hostOf(urlStr) {
  try { return new URL(urlStr).host; } catch { return ""; }
}
function appendRedirect(fromUrl, toUrl) {
  const prev = (redirectChains.get(fromUrl)?.hosts) || [hostOf(fromUrl)].filter(Boolean);
  const nextHost = hostOf(toUrl);
  const chain = [...prev, nextHost].filter(Boolean);
  redirectChains.set(toUrl, { hosts: chain, ts: Date.now() });
  // fromUrl 키는 더 이상 사용할 일이 적으니 제거해 메모리 누수 방지
  redirectChains.delete(fromUrl);
}
function chainFor(urlStr) {
  const ent = redirectChains.get(urlStr);
  if (ent && ent.hosts && ent.hosts.length) return ent.hosts;
  const h = hostOf(urlStr);
  return h ? [h] : [];
}
function sweepChains() {
  const now = Date.now();
  for (const [k, v] of redirectChains) {
    if (!v || !v.ts || (now - v.ts > REDIRECT_CHAIN_TTL_MS)) redirectChains.delete(k);
  }
}
setInterval(sweepChains, 60 * 1000).unref();

let featureExtractor, mlClient;

try {
    featureExtractor = require("./featureExtractor");
    /*
    featureExtractor = {
        extract: async () => ({})
    };
    */

} 
catch {
    featureExtractor = { extract: async () => ({}) };
}
try {
    mlClient = require("./mlClient");
    /*
    mlClient = {
        predict: async () => ({ result: "test" })
    };
    */
    
} 

catch {
    mlClient = {
        predict: async () => ({ result: "phishing" })
    };
}

//헤더가 이미 전송되었으면 writeHead를 재호출하지 않음 
function safeRespond(ctx, statusCode, headers, bodyBuf) {
  const res = ctx.proxyToClientResponse;
  if (!res || res.destroyed || res.writableEnded) return;
  try {
    if (!res.headersSent) res.writeHead(statusCode, headers);
    if (bodyBuf && bodyBuf.length) {
      res.end(bodyBuf);
    } else {
      res.end();
    }
  } catch (err) {
    // 소켓이 이미 닫혔거나 쓰기 불가한 경우 무시
  }
}

//메인 문서인지 아닌지
function isTopLevelDocument(req) {
    const h = (req && req.headers) || {};//req와 헤더가 존재할 경우 h에 담고 아니면 빈 객체
    const dest = String(h["sec-fetch-dest"] || "").toLowerCase();//소문자로 해서 표기 다르더라도 통용되게
    return dest === "document";//document 즉 메인 문서가 맞으면 true 반환
}

function maybeDecompress(buf, encoding) {
  return new Promise((resolve, reject) => {
    const enc = String(encoding || "").toLowerCase();
    if (!buf || !buf.length) return resolve(Buffer.alloc(0));
    if (!enc || enc === "identity") return resolve(buf);
    if (enc.includes("gzip")) return zlib.gunzip(buf, (e, out) => e ? reject(e) : resolve(out));
    if (enc.includes("deflate")) return zlib.inflate(buf, (e, out) => e ? reject(e) : resolve(out));
    if (enc.includes("br")) return zlib.brotliDecompress(buf, (e, out) => e ? reject(e) : resolve(out));
    return resolve(buf);
  });
}

let _browser = null;
async function getPuppeteerBrowser() {
  if (!puppeteer) throw new Error("puppeteer not installed");
  if (_browser && _browser.isConnected()) return _browser;
  _browser = await puppeteer.launch({
    headless: true,
    args: ["--no-sandbox", "--disable-setuid-sandbox"], 
    defaultViewport: { width: 1280, height: 800, deviceScaleFactor: 1 }
  });
  return _browser;
}

async function renderHTMLWithPuppeteer({ html, baseUrl, host, saveScreenshot = true }) {
  if (!puppeteer) return null; 
  if (!html || !html.trim()) return null;
  const browser = await getPuppeteerBrowser();
  const page = await browser.newPage();

  try {
    await page.setRequestInterception(true);
    const origin = (() => { try { return baseUrl ? new URL(baseUrl).origin : null; } catch { return null; } })();
    page.on("request", req => {
      const url = req.url();
      if (url.startsWith("data:")) return req.continue();
      if (origin) {
        try { if (new URL(url).origin === origin) return req.continue(); } catch {}
      }
      return req.abort();
    });
  } catch (_) { /* 무시 */ }

  await page.setContent(html, { waitUntil: "domcontentloaded" });
  if (baseUrl) {
    try {
      await page.evaluate((b) => {
        if (!document.querySelector('base')) {
          const el = document.createElement('base');
          el.setAttribute('href', b);
          document.head.prepend(el);
        }
      }, baseUrl);
    } catch (_) {}
  }

  await delay(150);
  const renderedHTML = await page.content();

  let screenshotPath = null;
  if (saveScreenshot) {
    const outDir = path.resolve(__dirname, "..", "renders");
    try { fs.mkdirSync(outDir, { recursive: true }); } catch (_) {}
    const ts = Date.now();
    const safeHost = String(host || "page").replace(/[^a-z0-9.-]/gi, "_");
    screenshotPath = path.join(outDir, `${ts}_${safeHost}.png`);
    await page.screenshot({ path: screenshotPath, fullPage: true });
    console.log(`[puppeteer] screenshot saved: ${screenshotPath}`);
  }
  await page.close();
  return { screenshotPath, renderedHTML };
}

process.on('exit', async () => { try { if (_browser) await _browser.close(); } catch (_) {} });
process.on('SIGINT', async () => { try { if (_browser) await _browser.close(); } catch (_) {} process.exit(0); });

const proxy = new Proxy();//프록시 생성자

proxy.onRequest((ctx, callback) => {
  try {
    if (!isTopLevelDocument(ctx.clientToProxyRequest)) return callback();
    const opts = ctx.proxyToServerRequestOptions || {};
    const hdrs = opts.headers ? { ...opts.headers } : {};
    hdrs['accept-encoding'] = 'identity'; // 서버에게 압축 금지 요청
    delete hdrs['te']; // 희귀한 TE: trailers 등 제거
    opts.headers = hdrs;
    ctx.proxyToServerRequestOptions = opts;
  } catch (_) {}
  return callback();
});

proxy.onConnect((req, clientSocket, head, cb) => {
  clientSocket.on('error', (err) => {
    if (err && (err.code === 'EPIPE' || err.code === 'ECONNRESET')) return;
    console.error('CLIENT_TO_PROXY_SOCKET error:', err);
  });
  cb();
});

proxy.onCertificateMissing = function(ctx, files, callback) {
  try {
    const caCertPem = fs.readFileSync(path.join(SSL_CA_DIR, "certs", "ca.pem"), "utf8");
    const caKeyPem  = fs.readFileSync(path.join(SSL_CA_DIR, "keys", "ca.private.key"), "utf8");

    const pki = forge.pki;
    const caCert = pki.certificateFromPem(caCertPem);
    const caKey  = pki.privateKeyFromPem(caKeyPem);

    const keys = pki.rsa.generateKeyPair(2048);

    const cert = pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = Buffer.from(crypto.randomBytes(16)).toString("hex").replace(/^0+/, "1");

    const now = new Date();
    cert.validity.notBefore = new Date(now.getTime() - 5 * 60 * 1000); 
    cert.validity.notAfter  = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);

    const hostname = ctx.hostname || "localhost";
    cert.setSubject([{ name: "commonName", value: hostname }]);
    cert.setIssuer(caCert.subject.attributes);

    const altNames = [{ type: 2, value: hostname }]; 
    const parts = hostname.split(".");
    if (parts.length >= 2) {
      const base = parts.slice(-2).join(".");
      altNames.push({ type: 2, value: "*." + base });
    }

    cert.setExtensions([
      { name: "basicConstraints", cA: false },
      { name: "keyUsage", digitalSignature: true, keyEncipherment: true },
      { name: "extKeyUsage", serverAuth: true },
      { name: "subjectAltName", altNames }
    ]);

    cert.sign(caKey, forge.md.sha256.create());

    const certPem = pki.certificateToPem(cert);
    const keyPem  = pki.privateKeyToPem(keys.privateKey);

    return callback(null, {
      keyFileData:  keyPem,
      certFileData: certPem,
      hosts: altNames.filter(x => x.type === 2).map(x => x.value)
    });
  } catch (e) {
    console.error("[cert-missing error]", e);
    return callback(e);
  }
};

proxy.onError((ctx, err, kind) => {//오류 났을때, ctx 는 오류난 http 트랜잭션, kind는 오류 종류
    if (err && (err.code === 'EPIPE' || err.code === 'ECONNRESET')) return; // 클라이언트 측 조기 종료: 무시
    const url = ctx?.clientToProxyRequest?.url || "";//clientToProxyRequest는 원본 http 요청 정보객체
    console.error(`[error 발생] kind=${kind} url=${url} err=${err?.message}`);
});


proxy.onResponse((ctx, callback) => {//응답 헤더가 프록시에 도착한 직후, 그리고 본문이 클라이언트로 스트리밍 되기 전의 이벤트
    const req = ctx.clientToProxyRequest;//요청 객체
    const res = ctx.serverToProxyResponse;//응답 객체

    if (!isTopLevelDocument(req)) {//요청객체에서 메인 문서인지 검사
        return callback();//아니면 그냥 그대로 포워드(여기서 콜백함수는 기본 동작을 계속 하는 동작을 함)
    }

    const chunks = [];//응답 본문이 클 수 있으니까 여러 조각으로 나눠서 도착함.그걸 위한 리스트

    ctx.onResponseData((ctx, chunk, cb) => {//또다른 이벤트 핸들러 등록. 청크가 하나 도착할때마다 실행
        if (chunk) {
            chunks.push(Buffer.from(chunk));//청크를 버퍼 형태로 변환해서 푸쉬함
        }
        // 원본을 곧바로 내보내지 않고 end에서 일괄 처리
        return cb(null, null);//첫번째 인자값은 에러, 두번째는 클라이언트에게 전달할꺼.
        //즉 에러도 없고 클라이언트로 보낼것도 없음.
    });

    ctx.onResponseEnd(async (ctx, cb) => {//서버로부터 받은 모든 응답 데이터가 도착해서 응답이 끝났을때
        try {
          const rawBodyBuf = Buffer.concat(chunks);

          const currentUrl = getRequestUrl(ctx);
          const status = res.statusCode || 200;
          const locHdr = res?.headers?.location;
          if (status >= 300 && status < 400 && locHdr) {
            const nextUrl = ensureAbsUrl(locHdr, currentUrl);
            if (nextUrl) appendRedirect(currentUrl, nextUrl);
            const pass3xxHeaders = { ...(res?.headers || {}) };
            delete pass3xxHeaders["transfer-encoding"];
            pass3xxHeaders["content-length"] = String(rawBodyBuf.length);
            safeRespond(ctx, status, pass3xxHeaders, rawBodyBuf);
            return cb();
          }

          const encodingHdr = ctx.serverToProxyResponse && ctx.serverToProxyResponse.headers ? ctx.serverToProxyResponse.headers['content-encoding'] : '';
          let plainBuf = rawBodyBuf;
          let html = '';
          try {
            plainBuf = await maybeDecompress(rawBodyBuf, encodingHdr);
            html = plainBuf.toString('utf8');
          } catch (_) {
            plainBuf = rawBodyBuf;
            html = '';
          }

          const host = req?.headers?.host || "";

          let domForExtractor = html; 
          if (renderSetting === 1 && puppeteer) {
            try {
              const scheme = 'https://';
              const baseUrl = host ? `${scheme}${host}/` : undefined;
              const { renderedHTML } = await renderHTMLWithPuppeteer({ html, baseUrl, host, saveScreenshot: true });
              if (renderedHTML && renderedHTML.trim()) domForExtractor = renderedHTML;
            } catch (e) {
              console.error('[puppeteer render error]', e);
            }
          }

          const redirectChainHosts = chainFor(currentUrl);
          const features = await featureExtractor.extract(
            req?.headers || {},
            res?.headers || {},
            redirectChainHosts,
            domForExtractor 
          );
          // 체인 엔트리는 최종 응답 시점에 정리
          redirectChains.delete(currentUrl);
          //console.log(redirectChainHosts)
          console.log(features)

          const decision = await mlClient.predict(features);



          if (decision?.result === "test" ) {
            safeRespond(ctx, 200, {
              "Content-Type": "text/html; charset=utf-8",
              "Content-Length": String(BLOCK_HTML.length),
              "Cache-Control": "no-store",
              "Pragma": "no-cache",
              "X-Content-Type-Options": "nosniff",
              "Connection": "close"
            }, BLOCK_HTML);
          }

          if (hostMatchesWhitelist(host)) {
            const passHeadersWL = { ...(res?.headers || {}) };
            delete passHeadersWL['content-encoding'];
            delete passHeadersWL['transfer-encoding'];
            delete passHeadersWL['content-length'];
            safeRespond(ctx, res.statusCode || 200, passHeadersWL, plainBuf);



            return cb();
          }

          if (decision?.result === "phishing" && isTopLevelDocument(req)) {
            safeRespond(ctx, 200, {
              "Content-Type": "text/html; charset=utf-8",
              "Content-Length": String(BLOCK_HTML.length),
              "Cache-Control": "no-store",
              "Pragma": "no-cache",
              "X-Content-Type-Options": "nosniff",
              "Connection": "close"
            }, BLOCK_HTML);
          } else {
            const passHeaders = { ...(res?.headers || {}) };
            delete passHeaders['content-encoding'];
            delete passHeaders['transfer-encoding'];
            delete passHeaders['content-length']; 
            safeRespond(ctx, res.statusCode || 200, passHeaders, plainBuf);
          }
        }
        catch(e) {
          console.error("[에러 내용]", e);
          const rawBodyBuf = Buffer.concat(chunks);
          const passHeaders = { ...(res?.headers || {}) };
          delete passHeaders["transfer-encoding"];
          passHeaders["content-length"] = String(rawBodyBuf.length);
          safeRespond(ctx, res.statusCode || 200, passHeaders, rawBodyBuf);
        }
        return cb();
    });

    return callback();
});

proxy.listen({ host: "0.0.0.0", port: PORT, sslCaDir: SSL_CA_DIR }, () => {
  console.log(`↪ proxy listening at http://0.0.0.0:${PORT}`);//sslCaDir의 값으로 전달한 디렉터리 내에서 ca-key.pem을 찾아서 서명한 후 인증서를 브라우저에 제출
});
