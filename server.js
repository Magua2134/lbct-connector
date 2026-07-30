// ============================================
// EModal + LBCT Connector - Standalone Node.js + Express Service
// Deployed on Render/Railway to avoid WAF/rate-limiting issues
// ============================================

// 本地开发: 加载 .env (Render 会自动注入环境变量，不需要 dotenv 生产依赖)
try { require('dotenv').config({ override: false }); } catch (e) {}

// ⚠️ 禁用 SSL 严格验证：解决 portal.lbct.com 证书链不完整问题
// 这是码头网站常见问题（自签名/过期/中间证书缺失），作为内部代理可接受
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
console.log('[TLS] NODE_TLS_REJECT_UNAUTHORIZED=0 (SSL certificate verification disabled for LBCT)');

const express = require('express');
const cors = require('cors');

// 2Captcha 客户端 (用于 LBCT reCAPTCHA v2 自动打码)
const { TwoCaptchaClient } = require('./2captcha');
const TWO_CAPTCHA_API_KEY = process.env.TWOCAPTCHA_API_KEY || '';
const twoCaptcha = TWO_CAPTCHA_API_KEY ? new TwoCaptchaClient(TWO_CAPTCHA_API_KEY) : null;
console.log('[2Captcha] ' + (twoCaptcha ? 'Initialized (key=****' + TWO_CAPTCHA_API_KEY.slice(-4) + ')' : 'DISABLED - no TWOCAPTCHA_API_KEY'));

// Ensure Web Crypto API is available globally (Node 18+)
if (typeof globalThis.crypto === 'undefined') {
  globalThis.crypto = require('crypto').webcrypto;
}

// ============================================
// Proxy support: route all outbound requests through a proxy
// Set PROXY_URL env var (e.g., http://user:pass@proxy:port) to enable
// ============================================
try {
  var undici = require('undici');
  if (process.env.PROXY_URL) {
    var proxyAgent = new undici.ProxyAgent(process.env.PROXY_URL);
    undici.setGlobalDispatcher(proxyAgent);
    console.log('[Proxy] Global proxy set to:', process.env.PROXY_URL.replace(/\/\/[^:]+:[^@]+@/, '//***:***@'));
  } else {
    console.log('[Proxy] No PROXY_URL set, using direct connection');
  }
} catch (e) {
  console.warn('[Proxy] Failed to init proxy (will use direct connection):', e.message);
}

// ============================================
// Helper functions (copied from paid-version/src/terminals/index.js lines 6-107)
// ============================================

function extractTime(slotName) {
  var m = slotName.match(/(\d{1,2}:\d{2})/);
  if (!m) return null;
  var parts = m[1].split(":");
  return String(parseInt(parts[0], 10)).padStart(2, "0") + ":" + parts[1];
}

// ====== EModal OAuth2 PKCE 辅助函数 ======
function generateRandomString(length) {
  var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
  var result = "";
  var arr = new Uint8Array(length);
  crypto.getRandomValues(arr);
  for (var i = 0; i < length; i++) result += chars[arr[i] % chars.length];
  return result;
}

async function sha256Base64Url(message) {
  var enc = new TextEncoder();
  var data = enc.encode(message);
  var hashBuf = await crypto.subtle.digest("SHA-256", data);
  var bytes = new Uint8Array(hashBuf);
  var bin = "";
  for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// 从 HTML 中提取 hidden input 值
function extractHiddenField(html, name) {
  var m = html.match(new RegExp('name="' + name + '"[^>]*value="([^"]*)"', "i"));
  if (!m) m = html.match(new RegExp('value="([^"]*)"[^>]*name="' + name + '"', "i"));
  return m ? m[1] : "";
}

// 从 HTML 中提取所有 hidden input
function extractAllHiddenFields(html) {
  function decodeEntities(s) {
    return s.replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'");
  }
  function getAttr(tag, name) {
    // 匹配 name=value (支持双引号、单引号、无引号)
    // name 前后非 word char 或开头/结尾，避免匹配更长属性名
    var safe = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    var re = new RegExp("(?:^|\\s)" + safe + "\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s>\"']+))", "i");
    var m = tag.match(re);
    if (!m) return null;
    return m[1] !== undefined ? m[1] : (m[2] !== undefined ? m[2] : m[3]);
  }
  var fields = {};
  var re = /<input[^>]*>/gi;
  var m;
  while ((m = re.exec(html)) !== null) {
    var tag = m[0];
    var type = getAttr(tag, "type");
    if (!type) type = "text"; // default
    type = type.toLowerCase();
    if (type === "hidden") {
      var nm = getAttr(tag, "name");
      var vl = getAttr(tag, "value");
      if (nm !== null) {
        if (!fields[nm]) fields[nm] = vl !== null ? decodeEntities(vl) : "";
      }
    }
  }
  return fields;
}

// 从 Set-Cookie 头提取 cookie (Node.js undici: getSetCookie(); Workers: getAll())
function extractCookies(headers) {
  var cookies = {};
  var setCookies;
  if (typeof headers.getSetCookie === "function") {
    setCookies = headers.getSetCookie();
  } else if (headers.getAll) {
    setCookies = headers.getAll("Set-Cookie");
  } else {
    setCookies = [headers.get("Set-Cookie")];
  }
  if (!setCookies || !setCookies[0]) return cookies;
  setCookies.forEach(function(sc) {
    if (!sc) return;
    var parts = sc.split(";");
    var nv = parts[0].trim().split("=");
    if (nv.length >= 2) cookies[nv[0].trim()] = nv.slice(1).join("=");
  });
  return cookies;
}

function cookiesToString(cookies) {
  return Object.keys(cookies).map(function(k) { return k + "=" + cookies[k]; }).join("; ");
}

// LBCT AES-128-CBC 加密 (key=IV=8080808080808080, PKCS7)
async function lbctEncrypt(plaintext) {
  var enc = new TextEncoder();
  var keyData = enc.encode("8080808080808080");
  var iv = enc.encode("8080808080808080");
  var key = await crypto.subtle.importKey("raw", keyData, { name: "AES-CBC" }, false, ["encrypt"]);
  var data = enc.encode(plaintext);
  var buf = await crypto.subtle.encrypt({ name: "AES-CBC", iv: iv }, key, data);
  var bytes = new Uint8Array(buf);
  var bin = "";
  for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function sleep(ms) {
  return new Promise(function(r) { setTimeout(r, ms); });
}

// ============================================
// TerminalClient 基类 (最小化版本, 无 subrequest 限制)
// ============================================
class TerminalClient {
  constructor(config) {
    this.config = config || {};
    this.baseUrl = config.baseUrl || "";
    this.cookie = config.cookie || "";
    this.username = config.username || "";
    this.password = config.password || "";
    this.token = config.token || "";
    this.truckInfo = { Plate_Nbr: "9G48988", Truck_Id: "671687" };
    this.jwt = null;
  }
}

// ============================================
// EModalClient 类 (从 paid-version/src/terminals/index.js 适配)
// 已移除 export 关键字和 subrequest 限制检查
// ============================================
class EModalClient extends TerminalClient {

  // 解析 AuthCookie (static 工具方法)
  static parseAuthCookie(raw) {
    if (!raw) return { accessToken: '', refreshToken: '', clientId: '' };
    var trimmed = String(raw).trim();
    if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) {
      var m = trimmed.match(/^Bearer\s+(.+)$/i);
      if (m) return { accessToken: m[1], refreshToken: '', clientId: '' };
      if (trimmed.length > 50) return { accessToken: trimmed, refreshToken: '', clientId: '' };
    }
    try {
      var obj = JSON.parse(trimmed);
      return {
        accessToken: obj.bearer || obj.access_token || obj.accessToken || '',
        refreshToken: obj.refresh_token || obj.refreshToken || '',
        clientId: obj.client_id || obj.clientId || 'PCEMODAL'
      };
    } catch (e) {
      try {
        var decoded = decodeURIComponent(trimmed);
        var obj2 = JSON.parse(decoded);
        return {
          accessToken: obj2.bearer || obj2.access_token || '',
          refreshToken: obj2.refresh_token || '',
          clientId: obj2.client_id || 'PCEMODAL'
        };
      } catch (e2) {
        return { accessToken: '', refreshToken: '', clientId: '' };
      }
    }
  }

  constructor(config) {
    super(config);
    this.baseUrl = "https://termops.emodal.com";
    this.gatewayUrl = "https://termops.emodal.com/pregategateway/api/pregate/RouteToBreApi";
    this.identityUrl = "https://sso.emodal.com";
    this.apiMode = config.apiMode || "native"; // native | draydog
    this.accessToken = "";
    this.refreshToken = "";
    this.draydogToken = "";
    this._parseCredentials(config);
  }

  // 从 config 中解析凭证 (password 字段存储 AuthCookie 或 DrayDog token)
  _parseCredentials(config) {
    var raw = config.password || config.token || config.authCookie || "";
    if (!raw) return;

    if (this.apiMode === "draydog") {
      this.draydogToken = raw;
      return;
    }

    // Native 模式: 解析 AuthCookie
    var trimmed = String(raw).trim();
    // 直接是 bearer token (非 JSON)
    if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) {
      var m = trimmed.match(/^Bearer\s+(.+)$/i);
      if (m) { this.accessToken = m[1]; return; }
      if (trimmed.length > 50) { this.accessToken = trimmed; return; }
    }
    try {
      var obj = JSON.parse(trimmed);
      this.accessToken = obj.bearer || obj.access_token || obj.accessToken || "";
      this.refreshToken = obj.refresh_token || obj.refreshToken || "";
    } catch (e) {
      try {
        var decoded = decodeURIComponent(trimmed);
        var obj2 = JSON.parse(decoded);
        this.accessToken = obj2.bearer || obj2.access_token || "";
        this.refreshToken = obj2.refresh_token || "";
      } catch (e2) {}
    }
  }

  // ====== 调用 truckerportal.emodal.com 原生端点 (绕过 pregategateway WAF) ======
  async callDirectPortal(controllerPath, requestType, data) {
    var method = (requestType || "GET").toUpperCase();
    // 去掉开头的 / 用来拼路径
    var path = controllerPath.startsWith("/") ? controllerPath : "/" + controllerPath;
    var url = "https://truckerportal.emodal.com" + path;
    var makeHeaders = function(token) {
      return {
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
        "Origin": "https://truckerportal.emodal.com",
        "Referer": "https://truckerportal.emodal.com/MyAppointments",
        "X-Requested-With": "XMLHttpRequest",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "sec-ch-ua": '"Not)A;Brand";v="99", "Google Chrome";v="127", "Chromium";v="127"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"
      };
    };
    var fetchOpts = {
      method: method,
      headers: makeHeaders(this.accessToken)
    };
    if (method !== "GET" && data !== undefined && data !== null) {
      fetchOpts.body = JSON.stringify(data);
    }
    var resp = await fetch(url, fetchOpts);
    if (resp.status === 401) throw { code: 401, message: "token_expired" };
    if (resp.status === 429) throw { code: 429, message: "rate_limited" };
    if (resp.status === 403) throw { code: 403, message: "HTTP 403: access_denied_by_waf_portal" };
    var text = await resp.text().catch(function() { return ""; });
    if (!resp.ok) throw { code: resp.status, message: "HTTP " + resp.status + ": " + text.slice(0, 200) };
    try { return JSON.parse(text); } catch (e) { return text; }
  }

  // ====== 调用 EModal API（统一入口）======
  // 策略：优先调用 truckerportal 原生端点（浏览器真实路径，WAF 最宽容，不易 403/429）
  // 仅当原生端点 404/405/endpoint 不支持时，才 fallback 到 pregategateway 方式
  async callGateway(controllerPath, requestType, data) {
    // ---- 第一步：原生端点 (truckerportal.emodal.com) ----
    // 先假设原生端点支持这个路径，直接试
    var method = (requestType || "GET").toUpperCase();
    var path = controllerPath.startsWith("/") ? controllerPath : "/" + controllerPath;
    // 去掉可能带的 query 参数（如 ?csrch=），原生端点有的支持有的不支持
    var url = "https://truckerportal.emodal.com" + path;

    var makePortalHeaders = function(token) {
      return {
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
        "Origin": "https://truckerportal.emodal.com",
        "Referer": "https://truckerportal.emodal.com/MyAppointments",
        "X-Requested-With": "XMLHttpRequest",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "sec-ch-ua": '"Not)A;Brand";v="99", "Google Chrome";v="127", "Chromium";v="127"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"
      };
    };

    var doPortalFetch = async function() {
      var fetchOpts = { method: method, headers: makePortalHeaders(this.accessToken) };
      if (method !== "GET" && data !== undefined && data !== null) {
        fetchOpts.body = JSON.stringify(data);
      }
      var resp = await fetch(url, fetchOpts);
      // 401: 尝试 refresh_token 一次
      if (resp.status === 401) {
        var refreshed = await this.refreshAccessToken();
        if (refreshed) {
          var fetchOpts2 = { method: method, headers: makePortalHeaders(this.accessToken) };
          if (method !== "GET" && data !== undefined && data !== null) {
            fetchOpts2.body = JSON.stringify(data);
          }
          var resp2 = await fetch(url, fetchOpts2);
          if (resp2.status === 401) throw { code: 401, message: "token_expired" };
          if (resp2.status === 429) throw { code: 429, message: "rate_limited" };
          // 404/405/403: 认为这个原生端点不支持/被拦，标记让外层 fallback 到 pregategateway
          if (resp2.status === 404 || resp2.status === 405) {
            return { _portalUnsupported: true, _status: resp2.status };
          }
          if (resp2.status === 403) {
            return { _portal403: true, _status: resp2.status };
          }
          var txt2 = await resp2.text().catch(function() { return ""; });
          if (!resp2.ok) throw { code: resp2.status, message: "HTTP " + resp2.status + ": " + txt2.slice(0, 200) };
          try { return JSON.parse(txt2); } catch (e) { return txt2; }
        }
        throw { code: 401, message: "token_expired" };
      }
      if (resp.status === 429) throw { code: 429, message: "rate_limited" };
      // 404/405：原生端点不支持（这个路径是 pregategateway 才有的），fallback
      if (resp.status === 404 || resp.status === 405) {
        return { _portalUnsupported: true, _status: resp.status };
      }
      // 403：原生也被拦了，尝试 pregategateway（不同域名也许 WAF 策略不同）
      if (resp.status === 403) {
        return { _portal403: true, _status: resp.status };
      }
      var txt = await resp.text().catch(function() { return ""; });
      if (!resp.ok) throw { code: resp.status, message: "HTTP " + resp.status + ": " + txt.slice(0, 200) };
      try { return JSON.parse(txt); } catch (e) { return txt; }
    }.bind(this);

    var res = await doPortalFetch();
    // 原生端点能用，直接返回（绝大多数情况走这里，快，1次请求，不429）
    if (!res || (typeof res !== "object") || (!res._portalUnsupported && !res._portal403)) {
      return res;
    }

    // ---- 第二步：原生端点不支持/403，fallback 到 pregategateway 一次（不带重试，省请求）----
    var payload = {
      data: data || null,
      controllerPath: controllerPath,
      requestType: requestType || "GET"
    };
    var makeGatewayHeaders = function(token) {
      return {
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
        "Origin": "https://truckerportal.emodal.com",
        "Referer": "https://truckerportal.emodal.com/",
        "X-Requested-With": "XMLHttpRequest",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
        "sec-ch-ua": '"Not)A;Brand";v="99", "Google Chrome";v="127", "Chromium";v="127"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"
      };
    };
    var doGatewayFetch = async function() {
      var resp = await fetch(this.gatewayUrl, {
        method: "POST",
        headers: makeGatewayHeaders(this.accessToken),
        body: JSON.stringify(payload)
      });
      if (resp.status === 401) {
        var refreshed = await this.refreshAccessToken();
        if (refreshed) {
          var resp2 = await fetch(this.gatewayUrl, {
            method: "POST",
            headers: makeGatewayHeaders(this.accessToken),
            body: JSON.stringify(payload)
          });
          if (resp2.status === 401) throw { code: 401, message: "token_expired" };
          if (resp2.status === 429) throw { code: 429, message: "rate_limited" };
          if (resp2.status === 403) throw { code: 403, message: "HTTP 403: access_denied_by_waf" };
          var txt2 = await resp2.text().catch(function() { return ""; });
          if (!resp2.ok) throw { code: resp2.status, message: "HTTP " + resp2.status + ": " + txt2.slice(0, 200) };
          try { return JSON.parse(txt2); } catch (e) { return txt2; }
        }
        throw { code: 401, message: "token_expired" };
      }
      if (resp.status === 429) throw { code: 429, message: "rate_limited" };
      if (resp.status === 403) throw { code: 403, message: "HTTP 403: access_denied_by_waf" };
      var txt = await resp.text().catch(function() { return ""; });
      if (!resp.ok) throw { code: resp.status, message: "HTTP " + resp.status + ": " + txt.slice(0, 200) };
      try { return JSON.parse(txt); } catch (e) { return txt; }
    }.bind(this);

    return await doGatewayFetch();
  }

  // ====== 使用 refresh_token 刷新 access_token ======
  async refreshAccessToken() {
    if (!this.refreshToken) return false;
    try {
      var resp = await fetch("https://sso.emodal.com/connect/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: "grant_type=refresh_token" +
          "&client_id=PCEMODAL" +
          "&refresh_token=" + encodeURIComponent(this.refreshToken)
      });
      if (!resp.ok) return false;
      var tokens = await resp.json();
      if (tokens.access_token) {
        this.accessToken = tokens.access_token;
        if (tokens.refresh_token) this.refreshToken = tokens.refresh_token;
        return true;
      }
    } catch (e) {}
    return false;
  }

  // ====== 直接调用其他官方 API ======
  async callDirect(url, method, data) {
    var headers = {
      "Authorization": "Bearer " + this.accessToken,
      "Accept": "application/json"
    };
    var body = undefined;
    if (data) {
      headers["Content-Type"] = "application/json";
      body = typeof data === "string" ? data : JSON.stringify(data);
    }
    var resp = await fetch(url, { method: method || "GET", headers: headers, body: body });
    if (resp.status === 401) throw { code: 401, message: "token_expired" };
    if (resp.status === 429) throw { code: 429, message: "rate_limited" };
    if (!resp.ok) {
      var t = await resp.text().catch(function() { return ""; });
      throw { code: resp.status, message: "HTTP " + resp.status + ": " + t.slice(0, 200) };
    }
    try { return await resp.json(); } catch (e) { return await resp.text(); }
  }

  // ====== DrayDog API 调用 ======
  async callDrayDog(method, path, data) {
    var headers = {
      "authorization": "Bearer " + this.draydogToken,
      "accept": "application/json"
    };
    if (data) headers["content-type"] = "application/json";
    var resp = await fetch("https://api.draydog.com" + path, {
      method: method,
      headers: headers,
      body: data ? JSON.stringify(data) : undefined
    });
    if (resp.status === 401) throw { code: 401, message: "token_expired_or_invalid" };
    if (resp.status === 429) throw { code: 429, message: "rate_limited" };
    if (!resp.ok) {
      var t = await resp.text().catch(function() { return ""; });
      throw { code: resp.status, message: "HTTP " + resp.status + ": " + t.slice(0, 200) };
    }
    var ct = resp.headers.get("Content-Type") || "";
    if (ct.indexOf("json") !== -1) return await resp.json();
    return await resp.text();
  }

  // ====== login(): 验证 Token 有效性 ======
  async login() {
    if (this.apiMode === "draydog") {
      if (!this.draydogToken) return { success: false, reason: "no_draydog_token" };
      try {
        var me = await this.callDrayDog("GET", "/users/current/info/");
        return { success: true, user: me };
      } catch (e) {
        return { success: false, reason: e.message || String(e) };
      }
    }

    if (!this.accessToken) return { success: false, reason: "no_access_token" };
    try {
      var info = await this.callDirect(this.identityUrl + "/identity/userinfo", "GET");
      return { success: true, user: info };
    } catch (e1) {
      try {
        var appInst = await this.callDirect(
          "https://api.appointments.visibility.emodal.com/api/AppInstance/getappinstance?InstanceUrl=PCEMODAL", "GET"
        );
        return { success: true, user: appInst };
      } catch (e2) {
        return { success: false, reason: "token_invalid: " + (e1.message || String(e1)) };
      }
    }
  }

  async checkAuth() {
    try {
      await this.login();
      return { valid: true };
    } catch (e) {
      return { valid: false };
    }
  }

  // ====== 账号密码自动登录 (双层 OAuth2) ======
  // 流程:
  // Step 1: Keycloak (sso.cargosprint.com) Outer OIDC Implicit Flow (response_type=id_token)
  //         → 获取 id_token (JWT) 用于 sso.emodal.com 建立本地会话
  // Step 2: POST id_token 到 sso.emodal.com/signin-oidc/keycloak (form_post)
  //         → sso.emodal.com (IdentityServer) 设置本地 Cookie
  // Step 3: 跟随重定向到 IdentityServer 内层 PKCE Authorize
  //         → 已经有本地会话 → 直接 302 回 truckerportal?code=...
  // Step 4: POST code → sso.emodal.com/connect/token 交换 access_token + refresh_token
  // ============================================================
  static async loginWithCredentials(username, password) {
    var allCookies = {};
    var ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

    function browserHeaders(extra) {
      var h = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1"
      };
      if (extra) Object.assign(h, extra);
      return h;
    }

    // 跟随重定向并累计 Cookies, 返回 { body, status, finalUrl }
    async function followRedirects(initialUrl, opts) {
      opts = opts || {};
      var method = opts.method || "GET";
      var body = opts.body;
      var hdrs = Object.assign({}, opts.headers || {});
      var maxR = opts.maxRedirects || 20;
      var url = initialUrl;
      var lastStatus = 0;
      var lastResp = null;
      var redirectTrace = [];

      while (maxR-- > 0) {
        var curUrlObj = new URL(url);
        var headers = browserHeaders(hdrs);
        // POST 请求需要 Origin/Referer/Sec-Fetch-Site
        if (method === "POST") {
          headers["Origin"] = curUrlObj.origin;
          headers["Referer"] = url;
          headers["Sec-Fetch-Site"] = "same-origin";
          headers["Sec-Fetch-Mode"] = "navigate";
          headers["Sec-Fetch-Dest"] = "document";
          headers["Sec-Fetch-User"] = "?1";
        }
        if (Object.keys(allCookies).length > 0) headers["Cookie"] = cookiesToString(allCookies);
        var fetchOpts = { method: method, redirect: "manual", headers: headers };
        if (body) fetchOpts.body = body;

        var r = await fetch(url, fetchOpts);
        lastResp = r;
        lastStatus = r.status;
        redirectTrace.push({ status: lastStatus, url: url.slice(0, 120) });
        Object.assign(allCookies, extractCookies(r.headers));

        var loc = r.headers.get("Location");
        if ((r.status === 301 || r.status === 302 || r.status === 303 || r.status === 307 || r.status === 308) && loc) {
          // 303: 总是 GET
          // 301/302: 浏览器行为：POST → GET + 丢弃 body (非标准但所有浏览器都这么做)
          // 307/308: 保留 method 和 body
          if (r.status === 303) {
            method = "GET"; body = undefined; if (hdrs["Content-Type"]) delete hdrs["Content-Type"];
          } else if (r.status === 301 || r.status === 302) {
            if (method === "POST") {
              method = "GET"; body = undefined; if (hdrs["Content-Type"]) delete hdrs["Content-Type"];
            }
          }
          if (loc.startsWith("http")) url = loc;
          else if (loc.startsWith("/")) { var u = new URL(url); url = u.origin + loc; }
          else { var u2 = new URL(url); var pp = u2.pathname.split("/"); pp.pop(); pp.push(loc); url = u2.origin + pp.join("/"); }
          continue;
        }

        var respBody = "";
        try { respBody = await r.text(); } catch (e) {}

        // 检查 HTML 中的自动跳转（sso.emodal.com 可能返回 200 + JS/meta/form 跳转）
        var autoUrl = null;
        var autoMethod = "GET";
        var autoBody = null;

        // 1. meta refresh: <meta http-equiv="refresh" content="0; url=...">
        var metaMatch = respBody.match(/http-equiv=["']refresh["'][^>]*content=["']\d*;\s*url=([^"']*)["']/i);
        if (metaMatch) autoUrl = metaMatch[1];

        // 2. JS redirect: window.location = "..." or location.href = "..." or location.replace("...")
        if (!autoUrl) {
          var jsMatch = respBody.match(/window\.location(?:\.href)?\s*=\s*["']([^"']+)["']/i);
          if (!jsMatch) jsMatch = respBody.match(/location(?:\.href)?\s*=\s*["']([^"']+)["']/i);
          if (!jsMatch) jsMatch = respBody.match(/location\.replace\(\s*["']([^"']+)["']\s*\)/i);
          if (jsMatch) autoUrl = jsMatch[1];
        }

        // 3. form auto-submit: <form action="..." method="post"> with onload/submit script
        if (!autoUrl) {
          var hasAutoSubmit = /document\.forms?\[?0?\]?\.submit|\.submit\(\)|onload.*submit/i.test(respBody);
          if (hasAutoSubmit) {
            var fAction = respBody.match(/<form[^>]*action="([^"]*)"/i);
            if (fAction) {
              autoUrl = fAction[1];
              autoMethod = "POST";
              // 提取 hidden fields
              var fFields = extractAllHiddenFields(respBody);
              autoBody = Object.keys(fFields).map(function(k) {
                return encodeURIComponent(k) + "=" + encodeURIComponent(fFields[k]);
              }).join("&");
              hdrs["Content-Type"] = "application/x-www-form-urlencoded";
            }
          }
        }

        // 4. 也在 <a href> 标签中查找带 code= 或 login-actions 的链接
        if (!autoUrl) {
          var aMatch = respBody.match(/<a[^>]*href=["']([^"']*(?:code=|login-actions|authenticate)[^"']*)["']/i);
          if (aMatch) autoUrl = aMatch[1];
        }

        if (autoUrl) {
          // 解析相对 URL
          if (autoUrl.startsWith("http")) {
            // already absolute
          } else if (autoUrl.startsWith("/")) {
            var au = new URL(url);
            autoUrl = au.origin + autoUrl;
          } else {
            var au2 = new URL(url);
            var ap = au2.pathname.split("/");
            ap.pop();
            ap.push(autoUrl);
            autoUrl = au2.origin + ap.join("/");
          }
          url = autoUrl;
          method = autoMethod;
          body = autoBody;
          if (autoMethod === "GET") {
            body = undefined;
            if (hdrs["Content-Type"]) delete hdrs["Content-Type"];
          }
          continue;
        }

        return { body: respBody, status: lastStatus, finalUrl: url, headers: r.headers, trace: redirectTrace };
      }

      var respBody2 = "";
      try { respBody2 = lastResp ? await lastResp.text() : ""; } catch (e) {}
      return { body: respBody2, status: lastStatus, finalUrl: url, headers: lastResp ? lastResp.headers : {}, trace: redirectTrace };
    }

    // ============================================================
    // Step 0: 先访问 sso.emodal.com/Account/Login?ReturnUrl=内层PKCE
    // 让 sso.emodal.com 生成并保存（Cookie里的）ReturnUrl, 然后重定向到 Keycloak 外层 id_token Flow
    // ============================================================
    var innerClientId = "PCEMODAL";
    var innerRedirectUri = "https://truckerportal.emodal.com/signin-oidc";
    var innerCodeVerifier = generateRandomString(64);
    var innerCodeChallenge = await sha256Base64Url(innerCodeVerifier);
    var innerState = generateRandomString(32);
    var innerNonce = generateRandomString(16);

    // 直接访问 IdentityServer Authorize 端点（不是 Account/Login）
    // IdentityServer 会自己 302 → /Account/Login?ReturnUrl=... → 302 → Keycloak auth
    var emodalLoginEntry = "https://sso.emodal.com/connect/authorize/callback"
      + "?client_id=" + innerClientId
      + "&redirect_uri=" + encodeURIComponent(innerRedirectUri)
      + "&response_type=code"
      + "&scope=" + encodeURIComponent("openid profile")
      + "&state=" + innerState
      + "&code_challenge=" + innerCodeChallenge
      + "&code_challenge_method=S256"
      + "&response_mode=query"
      + "&nonce=" + innerNonce;

    var s0 = await followRedirects(emodalLoginEntry);
    var loginHtml = s0.body || "";
    // 如果重定向链中最终的 URL(通常是 Keycloak sso.cargosprint.com 登录页)
    var keycloakFinalHtml = loginHtml;
    // 如果没有拿到足够长的内容，就回退
    if (!keycloakFinalHtml || keycloakFinalHtml.length < 100) {
      // 回退：直接访问 Keycloak 外层
      var nonce1 = generateRandomString(32) + "." + generateRandomString(32);
      var state1 = generateRandomString(128);
      var keycloakAuth = "https://sso.cargosprint.com/realms/master/protocol/openid-connect/auth"
        + "?client_id=pcemodal"
        + "&redirect_uri=" + encodeURIComponent("https://sso.emodal.com/signin-oidc/keycloak")
        + "&response_type=id_token"
        + "&scope=" + encodeURIComponent("openid profile")
        + "&response_mode=form_post"
        + "&nonce=" + encodeURIComponent(nonce1)
        + "&login_hint=" + encodeURIComponent(username)
        + "&appId=PCEMODAL"
        + "&state=" + encodeURIComponent(state1);
      var s0b = await followRedirects(keycloakAuth);
      keycloakFinalHtml = s0b.body || "";
      if (!keycloakFinalHtml || keycloakFinalHtml.length < 100) {
        var sn = keycloakFinalHtml.slice(0, 800);
        return { success: false, reason: "Step0_FAIL s0.status=" + s0.status + " s0b.status=" + s0b.status +
          "\ns0_trace=" + JSON.stringify(s0.trace||[]) + "\ns0_final=" + s0.finalUrl +
          "\ns0b_trace=" + JSON.stringify(s0b.trace||[]) + "\ns0b_final=" + s0b.finalUrl +
          "\nHTML:\n" + sn };
      }
    }

    // 如果 s0 已经有 code（已登录情况下）—— 这个 code 属于自己的 PKCE，可以直接换
    if (s0.finalUrl && s0.finalUrl.indexOf("code=") !== -1) {
      var cm00 = s0.finalUrl.match(/code=([^&]+)/);
      if (cm00) return await EModalClient._exchangeCode(decodeURIComponent(cm00[1]), innerCodeVerifier, innerRedirectUri, innerClientId, allCookies,
        "from=s0_code");
    }

    // ============================================================
    // Step 2: 提交第一阶段表单
    //   * 如果当前页是 sso.emodal.com 本地登录 → POST 用户名 (submit=next)
    //   * 如果当前页是 Keycloak → 直接 POST 用户名+密码到 Keycloak
    // ============================================================
    var step1Fields = extractAllHiddenFields(keycloakFinalHtml);
    var currentFinalUrl = s0.finalUrl;
    var isAtKeycloak = currentFinalUrl && currentFinalUrl.indexOf("sso.cargosprint.com") !== -1;

    var passHtml = "";
    var s2;
    var s3;

    if (!isAtKeycloak) {
      // ---- 路径A：当前在 sso.emodal.com 本地登录页（两步登录） ----
      step1Fields.Username = username;
      step1Fields.submit = "next";
      if (!step1Fields.ReCapthaToken) step1Fields.ReCapthaToken = "";

      var step1Url = currentFinalUrl;
      var step1Data = Object.keys(step1Fields).map(function(k) {
        return encodeURIComponent(k) + "=" + encodeURIComponent(step1Fields[k]);
      }).join("&");

      s2 = await followRedirects(step1Url, {
        method: "POST", body: step1Data,
        headers: { "Content-Type": "application/x-www-form-urlencoded" }
      });

      // POST username 后若出现 code（一步登录的极端情况）- 先不急着换，走 Step 4 保证 PKCE 匹配
      if (s2.finalUrl && s2.finalUrl.indexOf("code=") !== -1) {
        // 继续到 Step 4 自己 authorize 取新 code
      }
      passHtml = s2.body || "";

      // POST 用户名后 302 到 Keycloak？
      if (s2.finalUrl && s2.finalUrl.indexOf("sso.cargosprint.com") !== -1) {
        isAtKeycloak = true;
      }

      var passLowA = passHtml.toLowerCase();
      if (passHtml.indexOf("error-page") !== -1 || (passLowA.indexOf("alert-danger") !== -1 && passLowA.indexOf("invalid") !== -1)) {
        return { success: false, reason: "用户名验证失败 (本地校验)" };
      }
    }

    // ============================================================
    // Step 3: 提交第二阶段
    //   - 分支 A1：现在到 Keycloak 了 → POST username+password 到 login-actions/authenticate
    //   - 分支 A2：还在 sso.emodal.com → POST password 到本地
    // ============================================================
    if (isAtKeycloak) {
      // ---------- Keycloak 登录：POST username + password ----------
      var kcFields = {};
      // 从 passHtml 或 keycloakFinalHtml 提取 hidden fields
      var kcBaseHtml = passHtml && passHtml.length > 50 ? passHtml : keycloakFinalHtml;
      var kcHidden = extractAllHiddenFields(kcBaseHtml);
      Object.keys(kcHidden).forEach(function(k) { kcFields[k] = kcHidden[k]; });

      // 从 URL 中提取 session_code, execution, tab_id, client_id
      var kcFinalForParse = s2 ? (s2.finalUrl || currentFinalUrl) : currentFinalUrl;
      var scm = kcFinalForParse.match(/session_code=([^&]+)/);
      var exm = kcFinalForParse.match(/execution=([^&]+)/);
      var tbm = kcFinalForParse.match(/tab_id=([^&]+)/);
      var cim = kcFinalForParse.match(/client_id=([^&]+)/);
      if (scm && !kcFields.session_code) kcFields.session_code = decodeURIComponent(scm[1]);
      if (exm && !kcFields.execution) kcFields.execution = decodeURIComponent(exm[1]);
      if (tbm && !kcFields.tab_id) kcFields.tab_id = decodeURIComponent(tbm[1]);
      // username + password
      kcFields.username = username;
      kcFields.password = password;
      kcFields.rememberMe = "on";

      // Keycloak form action URL
      var kcAction = "";
      var kcForm = kcBaseHtml.match(/<form[^>]*action=["']([^"']*login-actions[^"']*)["']/i);
      if (kcForm) kcAction = kcForm[1];
      if (!kcAction || kcAction === "") {
        // 从 final URL 构建：/realms/master/login-actions/authenticate?session_code=...&execution=...&client_id=...&tab_id=...
        var kcBase = "https://sso.cargosprint.com/realms/master/login-actions/authenticate";
        var q = [];
        if (kcFields.session_code) q.push("session_code=" + encodeURIComponent(kcFields.session_code));
        if (kcFields.execution) q.push("execution=" + encodeURIComponent(kcFields.execution));
        if (cim) q.push("client_id=" + cim[1]); else q.push("client_id=pcemodal");
        if (kcFields.tab_id) q.push("tab_id=" + encodeURIComponent(kcFields.tab_id));
        kcAction = kcBase + (q.length ? "?" + q.join("&") : "");
      } else if (kcAction.startsWith("/")) {
        kcAction = "https://sso.cargosprint.com" + kcAction;
      } else if (!kcAction.startsWith("http")) {
        kcAction = "https://sso.cargosprint.com/" + kcAction;
      }

      // 移除 Keycloak URL query 中已经包含的重复字段（避免 double encode）
      var kcActionUrlObj = null;
      try { kcActionUrlObj = new URL(kcAction); } catch(e) {}
      if (kcActionUrlObj) {
        ["session_code","execution","client_id","tab_id"].forEach(function(p) {
          if (kcActionUrlObj.searchParams.get(p) && kcFields[p] !== undefined) delete kcFields[p];
        });
      }

      var kcData = Object.keys(kcFields).map(function(k) {
        return encodeURIComponent(k) + "=" + encodeURIComponent(kcFields[k]);
      }).join("&");

      s3 = await followRedirects(kcAction, {
        method: "POST", body: kcData,
        headers: { "Content-Type": "application/x-www-form-urlencoded" }
      });

      // Keycloak 登录成功后出现的 code：由于可能是外层层叠触发的（非我们的 PKCE），跳过，用 Step 4 自己的
      // followRedirects 已自动处理 form auto-submit
      // 如果 body 中有 code，也跳过，强制 Step 4
      var s3Html = s3.body || "";

      // Keycloak 登录失败？
      var s3Low = s3Html.toLowerCase();
      if (s3Low.indexOf("invalid username") !== -1 ||
          s3Low.indexOf("invalid password") !== -1 ||
          s3Low.indexOf("invalid user credentials") !== -1) {
        return { success: false, reason: "Keycloak 用户名或密码错误" };
      }
    } else {
      // ---------- 分支 A2：本地 sso.emodal.com 两步登录 - 密码页 ----------
      var step2Fields = extractAllHiddenFields(passHtml);
      if (!step2Fields.ReturnUrl && step1Fields.ReturnUrl) step2Fields.ReturnUrl = step1Fields.ReturnUrl;
      if (!step2Fields.ClientId && step1Fields.ClientId) step2Fields.ClientId = step1Fields.ClientId;
      if (!step2Fields.ReCapthaToken) step2Fields.ReCapthaToken = "";
      if (!step2Fields.__RequestVerificationToken && step1Fields.__RequestVerificationToken) {
        step2Fields.__RequestVerificationToken = step1Fields.__RequestVerificationToken;
      }
      var passInputMatch = passHtml.match(/<input[^>]*type=["']password["'][^>]*name=["']([^"']+)["']/i);
      var passFieldName = passInputMatch ? passInputMatch[1] : "Password";
      step2Fields[passFieldName] = password;
      var submitMatch = passHtml.match(/<button[^>]*type=["']submit["'][^>]*name=["']([^"']+)["'][^>]*value=["']([^"']*)["']/i);
      if (submitMatch) step2Fields[submitMatch[1]] = submitMatch[2];
      else step2Fields.submit = "login";
      var passFormAction = "";
      var pfm = passHtml.match(/<form[^>]*action="([^"]*)"/i);
      if (pfm) passFormAction = pfm[1];
      if (!passFormAction || passFormAction === "") passFormAction = s2.finalUrl;
      else if (passFormAction.startsWith("/")) passFormAction = "https://sso.emodal.com" + passFormAction;
      else if (!passFormAction.startsWith("http")) passFormAction = "https://sso.emodal.com/" + passFormAction;
      var step2Data = Object.keys(step2Fields).map(function(k) {
        return encodeURIComponent(k) + "=" + encodeURIComponent(step2Fields[k]);
      }).join("&");
      s3 = await followRedirects(passFormAction, {
        method: "POST", body: step2Data,
        headers: { "Content-Type": "application/x-www-form-urlencoded" }
      });
      // 强制跳过 Step 3 code，用 Step 4 自己的 PKCE code (保证匹配)
    }

    // ============================================================
    // Step 4：登录完成后，用我们自己的 innerState + PKCE 重新访问 authorize
    // 保证 code_challenge ↔ code_verifier 100% 对应，避免 invalid_grant
    // ============================================================
    var innerAuthUrl = "https://sso.emodal.com/connect/authorize/callback"
      + "?client_id=" + innerClientId
      + "&redirect_uri=" + encodeURIComponent(innerRedirectUri)
      + "&response_type=code"
      + "&scope=" + encodeURIComponent("openid profile")
      + "&state=" + innerState
      + "&code_challenge=" + innerCodeChallenge
      + "&code_challenge_method=S256"
      + "&response_mode=query"
      + "&nonce=" + innerNonce;
    var s4 = await followRedirects(innerAuthUrl);
    if (s4.finalUrl && s4.finalUrl.indexOf("code=") !== -1) {
      var cm6x = s4.finalUrl.match(/code=([^&]+)/);
      if (cm6x) return await EModalClient._exchangeCode(decodeURIComponent(cm6x[1]), innerCodeVerifier, innerRedirectUri, innerClientId, allCookies,
        "from=step4_authorize s4.status=" + s4.status);
    }
    var s4Body = s4.body || "";
    var jm4 = s4Body.match(/window\.location(?:\.href)?\s*=\s*["']([^"']*code=[^"']*)["']/i);
    if (!jm4) jm4 = s4Body.match(/location\.replace\(\s*["']([^"']*code=[^"']*)["']\s*\)/i);
    if (!jm4) jm4 = s4Body.match(/http-equiv=["']refresh["'][^>]*content=["']0;\s*url=([^"']*code=[^"']*)["']/i);
    if (!jm4) jm4 = s4Body.match(/<form[^>]*action=["']([^"']*code=[^"']*)["']/i);
    if (jm4) {
      var cm7x = jm4[1].match(/code=([^&]+)/);
      if (cm7x) return await EModalClient._exchangeCode(decodeURIComponent(cm7x[1]), innerCodeVerifier, innerRedirectUri, innerClientId, allCookies,
        "from=step4_body_parse s4.status=" + s4.status);
    }

    // 诊断输出：使用安全访问（部分分支变量可能未定义）
    function safe(p, d) { try { return p; } catch(e) { return d; } }
    var s3s = safe(s3 ? s3.status : "na");
    var s3f = safe(s3 ? s3.finalUrl : "na");
    var s3t = safe(s3 ? JSON.stringify(s3.trace) : "[]");
    var s2s = safe(s2 ? s2.status : "na");
    var s2f = safe(s2 ? s2.finalUrl : "na");
    var s2t = safe(s2 ? JSON.stringify(s2.trace) : "[]");
    var s3Body = safe(s3 ? s3.body || "" : "");
    var s4BodySafe = safe(s4.body || "");
    var step2F = safe(typeof step2Fields !== "undefined" ? Object.keys(step2Fields) : []);
    var passF = safe(typeof passFieldName !== "undefined" ? passFieldName : "");
    var kcFieldNames = isAtKeycloak ? Object.keys(kcFields || {}) : [];
    var finalDbg = "Step4_FAIL"
      + " isAtKeycloak=" + isAtKeycloak
      + " s3_status=" + s3s + " s3_final=" + s3f + "\n"
      + "s3_trace=" + s3t + "\n"
      + "s4_status=" + s4.status + " s4_final=" + s4.finalUrl + "\n"
      + "s4_trace=" + JSON.stringify(s4.trace) + "\n"
      + "Cookie_keys=" + JSON.stringify(Object.keys(allCookies)) + "\n"
      + "s2_status=" + s2s + " s2_final=" + s2f + "\n"
      + "s2_trace=" + s2t + "\n"
      + "s1_fields=" + JSON.stringify(Object.keys(step1Fields)) + "\n"
      + (isAtKeycloak
          ? "kc_fields=" + JSON.stringify(kcFieldNames) + " kc_action=" + kcAction + "\n"
          : "s2_passFields=" + JSON.stringify(step2F) + " passFieldName=" + passF + "\n")
      + "s3_HTML:\n" + s3Body.slice(0, 1500) + "\n"
      + "s4_HTML:\n" + s4BodySafe.slice(0, 1000) + "\n"
      + "passHtml:\n" + passHtml.slice(0, 1500);

    return { success: false, reason: finalDbg };
  }

  // 简化版 _exchangeTokenOnly: 用预设参数交换 token
  static async _exchangeTokenOnly(code) {
    return await EModalClient._exchangeCode(code, "", "https://truckerportal.emodal.com/signin-oidc", "PCEMODAL", {});
  }

  // 交换授权码获取 access_token
  static async _exchangeCode(code, codeVerifier, redirectUri, clientId, cookies, extraDbg) {
    var codeClean = code.split("&")[0].split("#")[0];
    var tokenResp = await fetch("https://sso.emodal.com/connect/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Cookie": cookiesToString(cookies)
      },
      body: "grant_type=authorization_code" +
        "&client_id=" + clientId +
        "&code=" + encodeURIComponent(codeClean) +
        "&code_verifier=" + codeVerifier +
        "&redirect_uri=" + encodeURIComponent(redirectUri)
    });

    if (!tokenResp.ok) {
      var errText = await tokenResp.text().catch(function() { return ""; });
      var dbg = "令牌交换失败: HTTP " + tokenResp.status + " " + errText.slice(0, 300) +
        "\ncodeLen=" + codeClean.length +
        "\nverifierLen=" + (codeVerifier || "").length +
        "\nredirect_uri=" + redirectUri +
        "\nclient_id=" + clientId +
        "\ncookie_count=" + Object.keys(cookies || {}).length;
      if (extraDbg) dbg += "\n" + extraDbg;
      return { success: false, reason: dbg };
    }

    var tokens = await tokenResp.json();
    var accessToken = tokens.access_token || "";
    var refreshToken = tokens.refresh_token || "";

    if (!accessToken) {
      return { success: false, reason: "令牌交换返回空 access_token" };
    }

    // 获取用户信息
    var user = {};
    try {
      var userResp = await fetch("https://sso.emodal.com/identity/userinfo", {
        headers: { "Authorization": "Bearer " + accessToken }
      });
      if (userResp.ok) user = await userResp.json();
    } catch (e) {}

    return {
      success: true,
      accessToken: accessToken,
      refreshToken: refreshToken,
      user: user,
      authCookie: JSON.stringify({ bearer: accessToken, refresh_token: refreshToken, client_id: clientId })
    };
  }

  // ====== getBooking(container): 查询已有预约 ======
  async getBooking(container) {
    if (this.apiMode === "draydog") {
      try {
        var after = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
        var before = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
        var all = await this.callDrayDog("GET", "/appointments/with_container_info/?after=" + encodeURIComponent(after) + "&before=" + encodeURIComponent(before));
        if (Array.isArray(all)) {
          var cUp = String(container || "").toUpperCase();
          for (var j = 0; j < all.length; j++) {
            var it = all[j];
            var slot = it.slot || {};
            var cc = (slot.container_number || it.container_number || "").toString().toUpperCase();
            if (cc === cUp) {
              return { gateApptId: it.id || slot.id || "", truckVisitApptId: 0, container: container, raw: it };
            }
          }
        }
      } catch (e) {}
      return null;
    }

    // Native 模式: 通过 SearchMyAppointments 查询
    try {
      var today = new Date();
      var laOpts = { timeZone: "America/Los_Angeles", month: "2-digit", day: "2-digit", year: "numeric" };
      var laStr = today.toLocaleDateString("en-US", laOpts);
      var parts = laStr.split("/");
      var fromDate = parts[0] + "/" + parts[1] + "/" + parts[2];

      var futureDate = new Date(); futureDate.setDate(futureDate.getDate() + 30);
      var laStr2 = futureDate.toLocaleDateString("en-US", laOpts);
      var parts2 = laStr2.split("/");
      var toDate = parts2[0] + "/" + parts2[1] + "/" + parts2[2];

      var conditions = [
        { mem: "fc-busn-dt-from", vLow: fromDate, vHigh: "" },
        { mem: "fc-busn-dt-to", vLow: toDate, vHigh: "" },
        { mem: "fc-cntr-nbr", vLow: container, vHigh: "" }
      ];
      var payload = {
        key: null,
        viewName: "VisitView",
        pageSize: 50,
        Page: 1,
        conditions: conditions,
        sortFields: [],
        sortDirection: "asc"
      };
      var result = await this.callGateway("/Visit/SearchMyAppointments?csrch=", "POST", payload);

      var list = [];
      if (Array.isArray(result)) list = result;
      else if (result && Array.isArray(result.data)) list = result.data;
      else if (result && result.results) list = result.results;
      else if (result && result.items) list = result.items;

      if (!list.length) return null;

      var cUp = String(container || "").toUpperCase();
      for (var i = 0; i < list.length; i++) {
        var item = list[i];
        var cc = (item.containerNo || item.containerNumber || item.container || item.cntrNbr || item.cntr_no || "").toString().toUpperCase();
        if (cc === cUp) {
          var id = item.visitId || item.appointmentId || item.id || item.visit_id || "";
          if (!id && item.rowId) id = item.rowId;
          return {
            gateApptId: String(id),
            truckVisitApptId: 0,
            container: container,
            raw: item,
            appointmentTime: item.appointmentDate || item.date || item.businessDate || ""
          };
        }
      }
    } catch (e) {}
    return null;
  }

  // ====== getSlotsByDate(): 查询可用时段 ======
  async getSlotsByDate(targetDate, containerNo, gateApptId, targetTime) {
    if (this.apiMode === "draydog") {
      var params = new URLSearchParams();
      params.set("terminal", "LBCT");
      params.set("date", targetDate);
      var path = "/appointments/availability/" + encodeURIComponent(containerNo) + "/?" + params.toString();
      var data = await this.callDrayDog("GET", path);
      return this._parseDrayDogSlots(data, targetDate);
    }

    // Native 模式: 多端点候选
    var candidates = [
      { path: "/Visit/GetAvailableSlots", type: "POST", data: { containerNo: containerNo, container: containerNo, terminal: "LBCT", facility: "LBCT", date: targetDate, appointmentDate: targetDate } },
      { path: "/visitnextgen/GetAvailableSlots", type: "POST", data: { container: containerNo, containerNo: containerNo, facility: "LBCT", terminal: "LBCT", appointmentDate: targetDate, date: targetDate } },
      { path: "/GateSlot/GetAvailableGateSlots", type: "POST", data: { containerNumber: containerNo, container: containerNo, terminal: "LBCT", facility: "LBCT", date: targetDate } },
      { path: "/visitnextgen/GetGateSlots", type: "POST", data: { container: containerNo, facility: "LBCT", appointmentDate: targetDate } },
      { path: "/Appointment/GetAvailableTimeSlots", type: "POST", data: { containerNo: containerNo, terminalCode: "LBCT", appointmentDate: targetDate } }
    ];

    var lastError = null;
    for (var ci = 0; ci < candidates.length; ci++) {
      try {
        var result = await this.callGateway(candidates[ci].path, candidates[ci].type, candidates[ci].data);
        var slots = this._extractSlots(result);
        if (slots && slots.length > 0) {
          return this._buildSlotMap(slots);
        }
      } catch (e) {
        lastError = e;
      }
    }
    return {};
  }

  _parseDrayDogSlots(data, date) {
    var slotMap = {};
    if (!data) return slotMap;
    var slots = [];
    if (Array.isArray(data)) slots = data;
    else if (data.slots) slots = data.slots;
    else if (data.availableSlots) slots = data.availableSlots;
    else if (data.data && Array.isArray(data.data)) slots = data.data;

    for (var i = 0; i < slots.length; i++) {
      var s = slots[i];
      var timeStr = s.window_start || s.start || s.time || s.slot || "";
      var tk = extractTime(timeStr);
      if (tk) {
        slotMap[tk] = { slot: timeStr, id: String(s.id || tk), gate: "LBCT" };
      }
    }
    return slotMap;
  }

  _extractSlots(result) {
    if (!result) return [];
    if (Array.isArray(result)) return result;
    if (result.data) {
      if (Array.isArray(result.data)) return result.data;
      if (result.data.slots) return result.data.slots;
      if (result.data.availableSlots) return result.data.availableSlots;
      if (result.data.available) return result.data.available;
      if (result.data.timeSlots) return result.data.timeSlots;
      if (result.data.gateSlots) return result.data.gateSlots;
    }
    if (result.slots) return result.slots;
    if (result.availableSlots) return result.availableSlots;
    if (result.available) return result.available;
    if (result.results) return result.results;
    if (result.timeSlots) return result.timeSlots;
    return [];
  }

  _buildSlotMap(slots) {
    var slotMap = {};
    for (var i = 0; i < slots.length; i++) {
      var s = slots[i];
      if (typeof s === "string") {
        var tk1 = extractTime(s);
        if (tk1) slotMap[tk1] = { slot: s, id: s, gate: "LBCT" };
        continue;
      }
      var timeStr = s.time || s.slotTime || s.label || s.window_start || s.start || s.slot || s.timeSlot || "";
      var tk2 = extractTime(timeStr);
      if (tk2) {
        var id = s.id || s.slotId || s.slot_id || s.appointmentSlotId || tk2;
        var gate = s.gate || s.terminal || s.facility || "LBCT";
        slotMap[tk2] = { slot: timeStr, id: String(id), gate: gate };
      }
    }
    return slotMap;
  }

  // ====== createBooking(): 创建/修改预约 ======
  async createBooking(container, date, time, options) {
    options = options || {};
    var existing = options.existingAppt || null;
    var slotMap = options.slotMap || null;

    // 获取匹配的 slot
    var matchedSlot = null;
    if (slotMap && slotMap[time]) matchedSlot = slotMap[time];
    else if (slotMap) {
      var hour = time.split(":")[0];
      var keys = Object.keys(slotMap).sort();
      for (var ki = 0; ki < keys.length; ki++) {
        if (keys[ki].startsWith(hour + ":")) { matchedSlot = slotMap[keys[ki]]; break; }
      }
    }
    var slotId = matchedSlot ? matchedSlot.slot : time;

    if (this.apiMode === "draydog") {
      var payload = {
        slot: {
          window_start: time,
          window_end: time,
          terminal: "LBCT",
          container_number: container
        }
      };
      var result = await this.callDrayDog("POST", "/appointments/booking/book/", payload);
      return {
        success: true,
        apptNo: result.id || result.appointment_id || "",
        time: time,
        date: date,
        timeSlot: time
      };
    }

    // Native 模式: 多端点候选
    var bookPayload = {
      containerNo: container,
      containerNumber: container,
      container: container,
      terminal: "LBCT",
      facility: "LBCT",
      appointmentDate: date,
      date: date,
      timeSlot: time,
      slot: slotId,
      windowStart: time,
      windowEnd: time
    };

    var endpoints;
    if (existing && existing.gateApptId) {
      // 修改路径
      var aid = existing.gateApptId;
      Object.assign(bookPayload, { visitId: aid, appointmentId: aid, id: aid });
      endpoints = [
        { path: "/visitnextgen/UpdateVisit", type: "POST" },
        { path: "/Visit/UpdateAppointment", type: "POST" },
        { path: "/Visit/ModifyAppointment", type: "POST" },
        { path: "/Visit/ChangeSlot", type: "POST" },
        { path: "/visitnextgen/RescheduleVisit", type: "POST" }
      ];
    } else {
      // 创建路径
      endpoints = [
        { path: "/visitnextgen/CreateVisit", type: "POST" },
        { path: "/Visit/CreateAppointment", type: "POST" },
        { path: "/Visit/SubmitAppointment", type: "POST" },
        { path: "/visitnextgen/BookAppointment", type: "POST" },
        { path: "/Visit/Book", type: "POST" },
        { path: "/Appointment/Create", type: "POST" }
      ];
    }

    var lastError = null;
    for (var ei = 0; ei < endpoints.length; ei++) {
      try {
        var result2 = await this.callGateway(endpoints[ei].path, endpoints[ei].type, bookPayload);
        if (result2) {
          var ok = result2.success === true ||
            result2.appointmentId || result2.visitId || result2.id ||
            (result2.data && (result2.data.appointmentId || result2.data.visitId || result2.data.id || result2.data.success === true)) ||
            (result2.error === undefined && result2 !== null);
          if (ok) {
            var apptId = result2.appointmentId || result2.visitId || result2.id || "";
            if (!apptId && result2.data) apptId = result2.data.appointmentId || result2.data.visitId || result2.data.id || "";
            return {
              success: true,
              apptNo: String(apptId),
              time: time,
              date: date,
              timeSlot: time
            };
          }
        }
      } catch (e) {
        lastError = e;
      }
    }
    if (lastError) throw lastError;
    throw new Error("no_valid_endpoint");
  }

  async getAppointments() {
    if (this.apiMode === "draydog") {
      var after = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
      var before = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
      return await this.callDrayDog("GET", "/appointments/with_container_info/?after=" + encodeURIComponent(after) + "&before=" + encodeURIComponent(before));
    }

    var today = new Date();
    var laOpts = { timeZone: "America/Los_Angeles", month: "2-digit", day: "2-digit", year: "numeric" };
    var laStr = today.toLocaleDateString("en-US", laOpts);
    var parts = laStr.split("/");
    var fromDate = parts[0] + "/" + parts[1] + "/" + parts[2];
    var conditions = [
      { mem: "fc-busn-dt-from", vLow: fromDate, vHigh: "" }
    ];
    var payload = {
      key: null, viewName: "VisitView", pageSize: 500, Page: 1,
      conditions: conditions, sortFields: [], sortDirection: "asc"
    };
    return await this.callGateway("/Visit/SearchMyAppointments?csrch=", "POST", payload);
  }

  async confirmBooking(apptId) {
    return { success: true };
  }

  // 取消预约
  async cancelAppointment(apptId) {
    if (this.apiMode === "draydog") {
      return await this.callDrayDog("DELETE", "/appointments/" + encodeURIComponent(apptId) + "/");
    }

    // Native 模式: 多端点候选
    var candidates = [
      { path: "/Visit/CancelVisit", type: "POST", data: { visitId: apptId, appointmentId: apptId } },
      { path: "/visitnextgen/CancelVisit", type: "POST", data: { visitId: apptId, appointmentId: apptId } },
      { path: "/Appointment/CancelAppointment", type: "POST", data: { appointmentId: apptId } },
      { path: "/Visit/DeleteVisit", type: "POST", data: { visitId: apptId } },
      { path: "/visitnextgen/DeleteVisit", type: "POST", data: { visitId: apptId } }
    ];
    var lastErr = null;
    for (var ci = 0; ci < candidates.length; ci++) {
      try {
        var result = await this.callGateway(candidates[ci].path, candidates[ci].type, candidates[ci].data);
        return { success: true, result: result };
      } catch (e) {
        lastErr = e;
      }
    }
    if (lastErr) throw lastErr;
    return { success: false, error: "no_valid_endpoint" };
  }
}

// ============================================
// LBCT Cookie Cache (in-memory)
// ============================================
// Map<username, {cookieStr, createdAt, expiresAt, csrf, extractedCsrf}>
const lbctCookieCache = new Map();
const LBCT_COOKIE_TTL = 7 * 60 * 60 * 1000; // 7小时 (LBCT 约 8 小时过期，提前1小时换)

// ============================================
// Cookie 工具函数
// ============================================
function mergeCookies(existingCookieStr, newSetCookie) {
  if (!newSetCookie) return existingCookieStr || "";
  // Parse the new Set-Cookie header: "name=value; path=/; expires=..."
  var firstPart = newSetCookie.split(";")[0].trim();
  if (!firstPart || firstPart.indexOf("=") === -1) return existingCookieStr || "";
  var newName = firstPart.split("=")[0].trim();
  var newValue = firstPart.split("=").slice(1).join("=").trim();

  if (!existingCookieStr) return firstPart;

  // Parse existing cookie string into name=value pairs
  var cookies = existingCookieStr.split(";").map(function(c) { return c.trim(); }).filter(Boolean);
  var found = false;
  var result = [];
  for (var i = 0; i < cookies.length; i++) {
    var c = cookies[i];
    if (c.indexOf(newName + "=") === 0) {
      result.push(newName + "=" + newValue);
      found = true;
    } else {
      result.push(c);
    }
  }
  if (!found) result.push(newName + "=" + newValue);
  return result.join("; ");
}

// ============================================
// LBCT 客户端 (Connector 专属版本 - 内置 2Captcha 自动登录)
// ============================================
class LBCTClientConnector {
  constructor(config) {
    this.config = config || {};
    this.baseUrl = "https://portal.lbct.com";
    this.cookieStr = config.cookie || "";
    this.csrfToken = config.csrfToken || "";
    this.extractedCsrf = config.extractedCsrf || "";
    this.username = config.username || "";
    this.password = config.password || "";
    this.ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
  }

  // ================ 基础 HTTP call（累积 Cookie + 跟随重定向） ================
  async call(method, path, data, contentType, overrideHeaders) {
    const headers = Object.assign({ "User-Agent": this.ua }, overrideHeaders || {});
    if (this.cookieStr) headers["Cookie"] = this.cookieStr;

    var opts = { method, headers, redirect: "manual" };
    if (data) {
      if (contentType === "form") {
        headers["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8";
        opts.body = new URLSearchParams(data).toString();
      } else {
        headers["Content-Type"] = "application/json; charset=UTF-8";
        opts.body = JSON.stringify(data);
      }
    }

    var url = path.startsWith("http") ? path : this.baseUrl + path;
    console.log("[LBCT] HTTP " + method + " " + url);
    const resp = await fetch(url, opts);
    console.log("[LBCT] HTTP " + method + " " + url + " → " + resp.status + " " + resp.statusText);
    this._accumulateCookies(resp);

    // 手动跟随 301/302 重定向（最多5层）
    var curResp = resp;
    var redirectsLeft = 5;
    while (redirectsLeft-- > 0 && (curResp.status === 301 || curResp.status === 302 || curResp.status === 303)) {
      var loc = curResp.headers.get("Location");
      if (!loc) break;
      if (loc.startsWith("/")) loc = this.baseUrl + loc;
      console.log("[LBCT] 🔄 Redirect " + resp.status + " → " + loc);
      var rh = { "User-Agent": this.ua };
      if (this.cookieStr) rh["Cookie"] = this.cookieStr;
      curResp = await fetch(loc, { method: "GET", headers: rh, redirect: "manual" });
      console.log("[LBCT] HTTP GET " + loc + " → " + curResp.status);
      this._accumulateCookies(curResp);
    }

    if (curResp.status === 401) {
      console.log("[LBCT] ❌ 401 Unauthorized - cookie expired");
      throw { code: 401, message: "cookie_expired" };
    }
    if (curResp.status === 403) {
      console.log("[LBCT] ❌ 403 Forbidden");
      throw { code: 403, message: "forbidden" };
    }
    if (!curResp.ok) {
      const txt = await curResp.text().catch(function(){ return ""; });
      console.log("[LBCT] ❌ HTTP " + curResp.status + ": " + txt.slice(0, 200));
      throw { code: curResp.status, message: "HTTP " + curResp.status + ": " + txt.slice(0, 300) };
    }

    const ct = curResp.headers.get("Content-Type") || "";
    if (ct.indexOf("json") !== -1) return await curResp.json();
    return await curResp.text();
  }

  _accumulateCookies(resp) {
    try {
      var list = [];
      // undici (Node.js 18+ fetch) 支持 getSetCookie() 返回数组
      if (typeof resp.headers.getSetCookie === "function") {
        list = resp.headers.getSetCookie();
      }
      // 兼容标准 fetch headers.get("set-cookie") 返回多行或逗号分隔
      if (!list || list.length === 0) {
        var raw = resp.headers.get("set-cookie") || resp.headers.get("Set-Cookie") || "";
        if (raw) {
          // undici 可能用 \n 或 ,\n 分隔多个 cookie
          list = raw.split(/\r?\n/).filter(Boolean);
        }
      }
      if (list.length > 0) {
        console.log("[LBCT] _accumulateCookies: found " + list.length + " Set-Cookie header(s)");
      }
      var oldLen = this.cookieStr ? this.cookieStr.length : 0;
      list.forEach(function(sc) {
        this.cookieStr = mergeCookies(this.cookieStr, sc);
        var m = sc.match(/__RequestVerificationToken=([^;]+)/);
        if (m) this.csrfToken = m[1];
      }.bind(this));
      var newLen = this.cookieStr ? this.cookieStr.length : 0;
      if (newLen !== oldLen) {
        console.log("[LBCT] Cookie updated: " + oldLen + " -> " + newLen + " bytes, cookieStr=" + (this.cookieStr ? this.cookieStr.substring(0, 80) + "..." : "(empty)"));
      }
    } catch(e) {
      console.error("[LBCT] _accumulateCookies ERROR:", e.message);
    }
  }

  // ================ 工具方法 ================
  extractCsrf(html) {
    if (typeof html !== "string") return "";
    var m = html.match(/__RequestVerificationToken.*?value="([^"]+)"/);
    if (m) this.extractedCsrf = m[1];
    return m ? m[1] : "";
  }
  extractSitekey(html) {
    if (typeof html !== "string") return "";
    var m = html.match(/data-sitekey=["']([^"']+)["']/i);
    return m ? m[1] : "";
  }

  // ================ 自动登录 (2Captcha) ================
  static async loginWithCredentials(username, password, captchaClient, options) {
    options = options || {};
    const loginUrl = options.loginUrl || "https://portal.lbct.com/LoginWithUrl/MyList";
    const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
    const client = new LBCTClientConnector({ username, password });

    if (!captchaClient) {
      return { success: false, error: "2Captcha client not initialized. Set TWOCAPTCHA_API_KEY env var." };
    }
    if (!username || !password) {
      return { success: false, error: "username and password required" };
    }

    try {
      // ---- Step 1: GET 登录页，提取 CSRF + sitekey ----
      var html = await client.call("GET", loginUrl);
      if (typeof html !== "string" || html.length < 50) {
        return { success: false, error: "failed to load login page (empty response)" };
      }
      var csrf = client.extractCsrf(html);
      var sitekey = client.extractSitekey(html);
      if (!sitekey) sitekey = "6LdpmKYUAAAAABfbOneCUYoKkKMzsXv_K0kfLPrA"; // LBCT 固定 sitekey，兜底
      console.log("[LBCT] Step1: loaded login page, csrf_len=" + csrf.length + ", sitekey=" + sitekey.slice(0,8) + "...");

      // ---- Step 2: 调 2Captcha 解 reCAPTCHA v2 ----
      var captchaTaskId = null;
      try {
        console.log("[LBCT] Step2: calling 2Captcha for reCAPTCHA v2...");
        var captchaRes = await captchaClient.solveRecaptchaV2({
          sitekey: sitekey,
          pageUrl: loginUrl,
          invisible: false,
          userAgent: ua
        });
        captchaTaskId = captchaRes.taskId;
        console.log("[LBCT] Step2: got captcha response, taskId=" + captchaTaskId + ", res_len=" + captchaRes.response.length);
        if (!captchaRes || !captchaRes.response) {
          return { success: false, error: "captcha solve failed: empty response" };
        }
        var gResponse = captchaRes.response;

        // ---- Step 3: 提交登录表单 ----
        console.log("[LBCT] Step3: submitting login form...");
        // LBCT 使用 "Email" 字段（某些版本可能用 "UserName"，两者都发）
        var formData = {
          Email: username,
          UserName: username,
          Password: password,
          __RequestVerificationToken: csrf || client.csrfToken || "",
          "g-recaptcha-response": gResponse,
          RememberMe: "false"
        };
        // 兼容 LBCT 可能存在的其他 hidden 字段
        var extra = extractAllHiddenFields(html);
        Object.keys(extra).forEach(function(k) {
          if (!formData[k] && extra[k] !== undefined) formData[k] = extra[k];
        });

        var loginRespHtml = await client.call("POST", "/LoginWithUrl/MyList", formData, "form");
        console.log("[LBCT] Step3: POST login returned, cookie_len=" + client.cookieStr.length + ", status=seen in call()");
        console.log("[LBCT] Step3: response preview: " + (typeof loginRespHtml === "string" ? loginRespHtml.substring(0, 200) : typeof loginRespHtml));
        if (client.cookieStr) {
          console.log("[LBCT] Step3: accumulated cookies: " + client.cookieStr.substring(0, 120) + (client.cookieStr.length > 120 ? "..." : ""));
        }
        if (typeof loginRespHtml === "string") {
          var lower = loginRespHtml.toLowerCase();
          if (lower.indexOf("login failed") !== -1 || lower.indexOf("invalid username") !== -1 ||
              lower.indexOf("invalid password") !== -1 || lower.indexOf("错误") !== -1) {
            if (captchaTaskId) {
              try { await captchaClient.reportBad(captchaTaskId); } catch(e) {}
            }
            return { success: false, error: "invalid username or password", html: loginRespHtml.slice(0,500) };
          }
        }

        // ---- Step 4: 验证 Cookie 有效性（GET /ViewMyList）----
        console.log("[LBCT] Step4: validating cookie...");
        client.extractCsrf(typeof loginRespHtml === "string" ? loginRespHtml : "");
        var valid = await client.validateCookie();
        if (!valid) {
          if (captchaTaskId) {
            try { await captchaClient.reportBad(captchaTaskId); } catch(e) {}
          }
          return { success: false, error: "login failed: cookie invalid after submit" };
        }

        // ---- 成功 ----
        console.log("[LBCT] ✅ Login success! Cookie valid, cookie_len=" + client.cookieStr.length);
        var now = Date.now();
        return {
          success: true,
          cookie: client.cookieStr,
          csrfToken: client.csrfToken,
          extractedCsrf: client.extractedCsrf,
          createdAt: now,
          expiresAt: now + LBCT_COOKIE_TTL,
          username: username,
          captchaTaskId: captchaTaskId
        };
      } catch(captchaErr) {
        return { success: false, error: "captcha error: " + (captchaErr.message || String(captchaErr)) };
      }
    } catch (e) {
      return { success: false, error: e.message || String(e) };
    }
  }

  async validateCookie() {
    try {
      console.log("[LBCT] validateCookie: GET /ViewMyList with cookie_len=" + (this.cookieStr ? this.cookieStr.length : 0));
      var html = await this.call("GET", "/ViewMyList");
      console.log("[LBCT] validateCookie: response type=" + typeof html + ", len=" + (typeof html === "string" ? html.length : 0));
      if (typeof html !== "string") { console.log("[LBCT] validateCookie: response is not a string!"); return false; }
      if (html.indexOf("LoginTimeout") !== -1) { console.log("[LBCT] validateCookie: ❌ LoginTimeout detected"); return false; }
      if (html.indexOf("window.location.href") !== -1 && html.length < 1500) { console.log("[LBCT] validateCookie: ❌ redirect loop detected (window.location.href)"); return false; }
      if (html.indexOf("LoginWithUrl/_returnUrl_") !== -1 && html.length < 1500) { console.log("[LBCT] validateCookie: ❌ redirected back to login"); return false; }
      if (html.indexOf("loginBoxLogin") !== -1 && html.indexOf("g-recaptcha") !== -1) { console.log("[LBCT] validateCookie: ❌ still on login page with captcha"); return false; }
      this.extractCsrf(html);
      console.log("[LBCT] validateCookie: ✅ Cookie valid (html_len=" + html.length + ")");
      return true;
    } catch(e) {
      console.log("[LBCT] validateCookie: ❌ Exception:", e.message);
      return false;
    }
  }

  // ================ 业务接口 ================
  async getSlotsByDate(targetDate, container) {
    try {
      var plaintext = "cntrId:" + container + ",transactionType:DI,equTypeVal:,lineOperVal:,bookingNumber:";
      var encrypted = await lbctEncrypt(plaintext);
      var result = await this.call("POST", "/Appointments/getAppointmentTimeSlotWidthId", { enc: encrypted });
      var slots = [];
      if (Array.isArray(result)) slots = result;
      else if (result && result.data && Array.isArray(result.data)) slots = result.data;
      else if (result && Array.isArray(result.Slots)) slots = result.Slots;
      var slotMap = {};
      for (var i = 0; i < slots.length; i++) {
        var s = slots[i];
        var slotName = s.Slot || s.slot || s.SlotName || s.Name || s.TimeSlot || "";
        var fakeId = s.FakeId || s.fakeId || s.FakeID || "";
        var quotaRuleGkey = s.QuotaRuleGkey || s.quotaRuleGkey || "";
        var slotDate = s.Date || s.date || s.ApptDate || "";
        if (slotDate) {
          var fd = slotDate;
          if (fd.indexOf("-") !== -1) {
            var dp = fd.split("-"); if (dp.length===3) fd = dp[1]+"/"+dp[2]+"/"+dp[0];
          }
          if (fd !== targetDate) continue;
        }
        var tk = extractTime(slotName);
        if (tk) slotMap[tk] = { slot: slotName, time: tk, fakeId: String(fakeId), quotaRuleGkey: String(quotaRuleGkey), date: slotDate || targetDate };
      }
      return slotMap;
    } catch(e) { return {}; }
  }

  async createBooking(container, date, time, options) {
    options = options || {};
    var slotMap = options.slotMap || {};
    var matched = slotMap[time];
    if (!matched) {
      // 按小时模糊匹配
      var hour = time.split(":")[0];
      var keys = Object.keys(slotMap).sort();
      for (var ki=0; ki<keys.length; ki++) { if (keys[ki].startsWith(hour+":")) { matched = slotMap[keys[ki]]; break; } }
    }
    if (!matched) throw new Error("no_slot_found: " + time);

    var apptData = {
      EqoiGkey: -1, TransactionType: "DI", LineOperation: "", ContainerId: container,
      SealNumber: "", SealNumber2: "", OrderId: "", FakeId: matched.fakeId || "",
      quotaRuleGkey: matched.quotaRuleGkey || "", equipType: "", LPN: ""
    };
    var fd = { oApptData: JSON.stringify(apptData) };
    if (this.extractedCsrf) fd.__RequestVerificationToken = this.extractedCsrf;
    else if (this.csrfToken) fd.__RequestVerificationToken = this.csrfToken;

    var result = await this.call("POST", "/Appointments/_DoCreateAppointmentByType", fd, "form");
    if (typeof result === "string") {
      if (result.indexOf("success") !== -1) {
        var m = result.match(/#(\d+)/);
        return { apptNo: m?m[1]:"N/A", time: date+" "+time, date, confirmed: true };
      }
      if (result.indexOf("Duplicate") !== -1 || result.indexOf("duplicate") !== -1) throw new Error("duplicate_appointment");
      throw new Error("booking_failed: " + result.slice(0,200));
    }
    if (result && (result.success || result.Success)) {
      return { apptNo: result.AppointmentNo || result.apptNo || "N/A", time: date+" "+time, date, confirmed: true };
    }
    throw new Error("booking_not_confirmed");
  }

  async getExistingAppointments() {
    try {
      var d = await this.call("POST", "/Appointments/GetAppointmentJson/", null);
      if (Array.isArray(d)) return d;
      if (d && Array.isArray(d.data)) return d.data;
      if (d && Array.isArray(d.Visits)) return d.Visits;
      return [];
    } catch(e) { return []; }
  }
}

// ============================================
// LBCT Cookie 管理
// ============================================
async function getValidLbctClient(username, password, force) {
  if (!username || !password) throw new Error("username and password required");
  if (!twoCaptcha) throw new Error("2Captcha not configured. Set TWOCAPTCHA_API_KEY env var.");

  // 查缓存
  if (!force) {
    var cached = lbctCookieCache.get(username);
    if (cached && cached.expiresAt > Date.now()) {
      var client = new LBCTClientConnector({
        username, password,
        cookie: cached.cookieStr,
        csrfToken: cached.csrfToken,
        extractedCsrf: cached.extractedCsrf
      });
      var valid = await client.validateCookie();
      if (valid) return client;
      // 缓存里的 cookie 已经过期，删掉
      lbctCookieCache.delete(username);
    }
  } else {
    lbctCookieCache.delete(username);
  }

  // 需要重新登录
  console.log("[LBCT] Auto-login for user:", username);
  var loginResult = await LBCTClientConnector.loginWithCredentials(username, password, twoCaptcha);
  if (!loginResult.success) {
    throw new Error("LBCT login failed: " + (loginResult.error || "unknown"));
  }
  // 写缓存
  lbctCookieCache.set(username, {
    cookieStr: loginResult.cookie,
    csrfToken: loginResult.csrfToken,
    extractedCsrf: loginResult.extractedCsrf,
    createdAt: loginResult.createdAt,
    expiresAt: loginResult.expiresAt
  });
  return new LBCTClientConnector({
    username, password,
    cookie: loginResult.cookie,
    csrfToken: loginResult.csrfToken,
    extractedCsrf: loginResult.extractedCsrf
  });
}

// ============================================
// Token Management Helper
// ============================================
async function getValidClient(username, password) {
  // Check cache first
  var cached = tokenCache.get(username);
  if (cached && cached.expiresAt > Date.now()) {
    // Try using cached token
    var client = new EModalClient({
      apiMode: 'native',
      password: cached.authCookie,
      token: cached.authCookie
    });
    return client;
  }

  // Need to login
  var loginResult = await EModalClient.loginWithCredentials(username, password);
  if (!loginResult.success) {
    throw { code: 401, message: 'Login failed: ' + (loginResult.reason || 'unknown') };
  }

  // Cache the token
  var authCookie = loginResult.authCookie || JSON.stringify({
    bearer: loginResult.accessToken,
    refresh_token: loginResult.refreshToken,
    client_id: 'PCEMODAL'
  });

  tokenCache.set(username, {
    accessToken: loginResult.accessToken,
    refreshToken: loginResult.refreshToken,
    authCookie: authCookie,
    expiresAt: Date.now() + TOKEN_CACHE_TTL
  });

  return new EModalClient({
    apiMode: 'native',
    password: authCookie,
    token: authCookie
  });
}

// ============================================
// Express Server
// ============================================
const app = express();
app.use(cors());
app.use(express.json());

// API Key 安全验证（支持 x-api-key 和 X-Connector-API-Key 两种 header）
const API_KEY = process.env.CONNECTOR_API_KEY || '';
app.use(function(req, res, next) {
  if (req.path === '/health') return next();
  if (API_KEY) {
    var key = req.headers['x-api-key'] || req.headers['x-connector-api-key'] || '';
    if (key !== API_KEY) {
      return res.status(403).json({ error: 'unauthorized: invalid or missing API key' });
    }
  }
  next();
});

// 1. Health check
app.get('/health', function(req, res) {
  res.json({ ok: true, timestamp: Date.now() });
});

// 2. Login with credentials
app.post('/api/emodal/login', async function(req, res) {
  var username = req.body && req.body.username;
  var password = req.body && req.body.password;
  if (!username || !password) {
    return res.status(400).json({ success: false, reason: 'username and password required' });
  }
  try {
    // Check token cache first
    var cached = tokenCache.get(username);
    if (cached && cached.expiresAt > Date.now()) {
      return res.json({
        success: true,
        accessToken: cached.accessToken,
        refreshToken: cached.refreshToken,
        authCookie: cached.authCookie,
        cached: true
      });
    }
    // Not cached, perform login
    var loginResult = await EModalClient.loginWithCredentials(username, password);
    if (!loginResult.success) {
      return res.status(401).json({ success: false, reason: loginResult.reason || 'login failed' });
    }
    var authCookie = loginResult.authCookie || JSON.stringify({
      bearer: loginResult.accessToken,
      refresh_token: loginResult.refreshToken,
      client_id: 'PCEMODAL'
    });
    tokenCache.set(username, {
      accessToken: loginResult.accessToken,
      refreshToken: loginResult.refreshToken,
      authCookie: authCookie,
      expiresAt: Date.now() + TOKEN_CACHE_TTL
    });
    res.json({
      success: true,
      accessToken: loginResult.accessToken,
      refreshToken: loginResult.refreshToken,
      authCookie: authCookie
    });
  } catch (e) {
    res.status(500).json({ success: false, reason: e.message || String(e) });
  }
});

// 3. List appointments
app.post('/api/emodal/appointments', async function(req, res) {
  var username = req.body && req.body.username;
  var password = req.body && req.body.password;
  if (!username || !password) {
    return res.status(400).json({ error: 'username and password required' });
  }
  try {
    var client = await getValidClient(username, password);
    var result;
    try {
      result = await client.getAppointments();
    } catch (e) {
      // If token expired (401), refresh/re-login and retry ONCE
      if (e && e.code === 401) {
        tokenCache.delete(username);
        client = await getValidClient(username, password);
        result = await client.getAppointments();
      } else {
        throw e;
      }
    }
    res.json({ success: true, appointments: result });
  } catch (e) {
    var code = (e && e.code) || 500;
    res.status(code).json({ error: e.message || String(e) });
  }
});

// 4. Query available slots
app.post('/api/emodal/slots', async function(req, res) {
  var username = req.body && req.body.username;
  var password = req.body && req.body.password;
  var container = req.body && req.body.container;
  var date = req.body && req.body.date;
  if (!username || !password) {
    return res.status(400).json({ error: 'username and password required' });
  }
  if (!container || !date) {
    return res.status(400).json({ error: 'container and date required' });
  }
  try {
    var client = await getValidClient(username, password);
    var result;
    try {
      result = await client.getSlotsByDate(date, container, null, null);
    } catch (e) {
      if (e && e.code === 401) {
        tokenCache.delete(username);
        client = await getValidClient(username, password);
        result = await client.getSlotsByDate(date, container, null, null);
      } else {
        throw e;
      }
    }
    res.json({ success: true, slots: result });
  } catch (e) {
    var code = (e && e.code) || 500;
    res.status(code).json({ error: e.message || String(e) });
  }
});

// 5. Create or modify appointment
app.post('/api/emodal/book', async function(req, res) {
  var username = req.body && req.body.username;
  var password = req.body && req.body.password;
  var container = req.body && req.body.container;
  var date = req.body && req.body.date;
  var time = req.body && req.body.time;
  var existingApptId = req.body && req.body.existingApptId;
  var terminal = req.body && req.body.terminal;
  if (!username || !password) {
    return res.status(400).json({ error: 'username and password required' });
  }
  if (!container || !date || !time) {
    return res.status(400).json({ error: 'container, date and time required' });
  }
  try {
    var client = await getValidClient(username, password);
    var options = {};
    if (existingApptId) {
      options.existingAppt = { gateApptId: existingApptId };
    }
    if (terminal) options.terminal = terminal;
    var result;
    try {
      result = await client.createBooking(container, date, time, options);
    } catch (e) {
      if (e && e.code === 401) {
        tokenCache.delete(username);
        client = await getValidClient(username, password);
        result = await client.createBooking(container, date, time, options);
      } else {
        throw e;
      }
    }
    res.json({ success: true, result: result });
  } catch (e) {
    var code = (e && e.code) || 500;
    res.status(code).json({ error: e.message || String(e) });
  }
});

// 6. Cancel appointment
app.post('/api/emodal/cancel', async function(req, res) {
  var username = req.body && req.body.username;
  var password = req.body && req.body.password;
  var appointmentId = req.body && req.body.appointmentId;
  if (!username || !password) {
    return res.status(400).json({ error: 'username and password required' });
  }
  if (!appointmentId) {
    return res.status(400).json({ error: 'appointmentId required' });
  }
  try {
    var client = await getValidClient(username, password);
    var result;
    try {
      result = await client.cancelAppointment(appointmentId);
    } catch (e) {
      if (e && e.code === 401) {
        tokenCache.delete(username);
        client = await getValidClient(username, password);
        result = await client.cancelAppointment(appointmentId);
      } else {
        throw e;
      }
    }
    res.json({ success: true, result: result });
  } catch (e) {
    var code = (e && e.code) || 500;
    res.status(code).json({ error: e.message || String(e) });
  }
});

// ============================================
// LBCT 端点组
// ============================================
// L1: 登录/刷新（自动用 2Captcha）
app.post('/lbct/login', async function(req, res) {
  var username = req.body && req.body.username;
  var password = req.body && req.body.password;
  var force = req.body && req.body.force;
  if (!username || !password) {
    return res.status(400).json({ success: false, error: 'username and password required' });
  }
  try {
    var client = await getValidLbctClient(username, password, !!force);
    var cached = lbctCookieCache.get(username);
    res.json({
      success: true,
      cookie: client.cookieStr,
      csrfToken: client.csrfToken,
      extractedCsrf: client.extractedCsrf,
      createdAt: cached ? cached.createdAt : Date.now(),
      expiresAt: cached ? cached.expiresAt : (Date.now() + LBCT_COOKIE_TTL),
      cached: !force
    });
  } catch (e) {
    res.status(401).json({ success: false, error: e.message || String(e) });
  }
});

// L2: 验证 Cookie 有效性
app.post('/lbct/validate', async function(req, res) {
  var username = req.body && req.body.username;
  var password = req.body && req.body.password;
  var cookie = (req.body && req.body.cookie) || "";
  try {
    var client;
    if (cookie) {
      client = new LBCTClientConnector({ cookie: cookie });
    } else if (username && password) {
      client = await getValidLbctClient(username, password, false);
    } else {
      return res.status(400).json({ success:false, error: "cookie or username+password required" });
    }
    var valid = await client.validateCookie();
    res.json({ success: true, valid: valid });
  } catch (e) {
    res.status(500).json({ success:false, valid:false, error: e.message || String(e) });
  }
});

// L3: 查询已有预约
app.post('/lbct/appointments', async function(req, res) {
  var username = req.body && req.body.username;
  var password = req.body && req.body.password;
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  try {
    var client = await getValidLbctClient(username, password, false);
    var list;
    try {
      list = await client.getExistingAppointments();
    } catch (e) {
      if (e && (e.code === 401 || e.message && e.message.indexOf("cookie_expired") !== -1)) {
        client = await getValidLbctClient(username, password, true);
        list = await client.getExistingAppointments();
      } else throw e;
    }
    res.json({ success: true, appointments: list });
  } catch (e) {
    var code = (e && e.code) || 500;
    res.status(code).json({ error: e.message || String(e) });
  }
});

// L4: 查询可用 slot
app.post('/lbct/slots', async function(req, res) {
  var username = req.body && req.body.username;
  var password = req.body && req.body.password;
  var container = req.body && req.body.container;
  var date = req.body && req.body.date;
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  if (!container || !date) return res.status(400).json({ error: 'container and date required' });
  try {
    var client = await getValidLbctClient(username, password, false);
    var map;
    try {
      map = await client.getSlotsByDate(date, container);
    } catch (e) {
      if (e && (e.code === 401 || (e.message && e.message.indexOf("cookie_expired") !== -1))) {
        client = await getValidLbctClient(username, password, true);
        map = await client.getSlotsByDate(date, container);
      } else throw e;
    }
    res.json({ success: true, slots: map, container: container, date: date });
  } catch (e) {
    var code = (e && e.code) || 500;
    res.status(code).json({ error: e.message || String(e) });
  }
});

// L5: 创建预约
app.post('/lbct/book', async function(req, res) {
  var username = req.body && req.body.username;
  var password = req.body && req.body.password;
  var container = req.body && req.body.container;
  var date = req.body && req.body.date;
  var time = req.body && req.body.time;
  var slotMap = req.body && req.body.slotMap;
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  if (!container || !date || !time) return res.status(400).json({ error: 'container, date and time required' });
  try {
    var client = await getValidLbctClient(username, password, false);
    var slots = slotMap || (await client.getSlotsByDate(date, container));
    var result;
    try {
      result = await client.createBooking(container, date, time, { slotMap: slots });
    } catch (e) {
      if (e && (e.code === 401 || (e.message && e.message.indexOf("cookie_expired") !== -1))) {
        client = await getValidLbctClient(username, password, true);
        slots = slotMap || (await client.getSlotsByDate(date, container));
        result = await client.createBooking(container, date, time, { slotMap: slots });
      } else throw e;
    }
    res.json({ success: true, result: result });
  } catch (e) {
    var code = (e && e.code) || 500;
    res.status(code).json({ error: e.message || String(e) });
  }
});

// L6: 2Captcha 余额查询
app.get('/lbct/balance', async function(req, res) {
  if (!twoCaptcha) return res.status(400).json({ success:false, error: "2Captcha not configured" });
  try {
    var balance = await twoCaptcha.getBalance();
    res.json({ success: true, balance: balance, currency: "USD" });
  } catch (e) {
    res.status(500).json({ success:false, error: e.message || String(e) });
  }
});

// L3: 诊断端点 - 逐步测试 LBCT 登录流程
app.get('/lbct/diagnose', async function(req, res) {
  var results = {};
  try {
    // Step 0: 测试基础连通性
    try {
      var r0 = await fetch("https://portal.lbct.com/ViewMyList", { method: "GET", redirect: "manual", headers: {"User-Agent": "Mozilla/5.0"} });
      results.step0 = { ok: true, status: r0.status };
    } catch(e0) {
      results.step0 = { ok: false, error: e0.message, stack: e0.stack, cause: e0.cause ? e0.cause.message : null };
    }

    // Step 1: 获取登录页
    try {
      var r1 = await fetch("https://portal.lbct.com/LoginWithUrl/MyList", { method: "GET", redirect: "manual", headers: {"User-Agent": "Mozilla/5.0"} });
      var html1 = await r1.text();
      results.step1 = { ok: true, status: r1.status, html_len: html1.length, hasSitekey: html1.indexOf("data-sitekey") !== -1 };
    } catch(e1) {
      results.step1 = { ok: false, error: e1.message, stack: e1.stack, cause: e1.cause ? e1.cause.message : null };
    }

    // Step 2: 测试 2Captcha API
    if (twoCaptcha) {
      try {
        var bal = await twoCaptcha.getBalance();
        results.step2 = { ok: true, balance: bal };
      } catch(e2) {
        results.step2 = { ok: false, error: e2.message };
      }
    }

    res.json({ success: true, results: results });
  } catch (e) {
    res.status(500).json({ success:false, error: e.message || String(e), results: results });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, function() {
  console.log('EModal Connector running on port ' + PORT);
});
