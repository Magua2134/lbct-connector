// ============================================
// 2Captcha 通用客户端 (reCAPTCHA v2 / v3 / hCaptcha)
// 仅成功计费，失败/超时不收费
// 文档: https://2captcha.com/api-docs/recaptcha-v2
// ============================================

const DEFAULT_API_URL = "https://2captcha.com";
// 可选备用节点 (如果主节点慢切下面这个)
// const DEFAULT_API_URL = "https://rucaptcha.com";

function sleep(ms) {
  return new Promise(function(r) { setTimeout(r, ms); });
}

class TwoCaptchaClient {
  /**
   * @param {object} opts
   * @param {string} opts.apiKey  - 2Captcha API Key (在 2captcha.com 后台设置里拿)
   * @param {string} [opts.apiUrl] - 可选自定义 API URL
   * @param {number} [opts.pollIntervalMs] - 轮询间隔 (默认 5s，符合官方推荐)
   * @param {number} [opts.maxWaitMs] - 最长等待时间 (默认 180s，reCAPTCHA v2 平均 15-30s)
   */
  constructor(opts) {
    opts = opts || {};
    this.apiKey = opts.apiKey || process.env.TWOCAPTCHA_API_KEY || "";
    this.apiUrl = opts.apiUrl || process.env.TWOCAPTCHA_API_URL || DEFAULT_API_URL;
    this.pollIntervalMs = opts.pollIntervalMs || 5000;
    this.maxWaitMs = opts.maxWaitMs || 180000;
    if (!this.apiKey) console.warn("[2Captcha] WARNING: apiKey 未设置，调用会失败");
  }

  // ========== 内部工具 ==========
  async _request(path, params, method) {
    method = method || "GET";
    var url = this.apiUrl + path;
    var opts = {
      method: method,
      headers: { "Accept": "application/json" }
    };
    if (method === "GET") {
      var qs = Object.keys(params).map(function(k) {
        return encodeURIComponent(k) + "=" + encodeURIComponent(params[k]);
      }).join("&");
      if (qs) url += "?" + qs;
    } else {
      opts.headers["Content-Type"] = "application/x-www-form-urlencoded";
      opts.body = Object.keys(params).map(function(k) {
        return encodeURIComponent(k) + "=" + encodeURIComponent(params[k]);
      }).join("&");
    }
    var r = await fetch(url, opts);
    var txt = await r.text();
    try { return JSON.parse(txt); } catch (e) {
      // 兼容纯文本 RESPONSE_STYLE (旧 API 默认)
      if (txt.indexOf("ERROR") === 0 || txt.indexOf("OK") === 0 || txt.indexOf("CAPCHA") === 0) {
        return { status: txt.indexOf("OK") === 0 ? 1 : 0, request: txt };
      }
      throw new Error("2Captcha 响应格式异常: " + txt.substring(0, 200));
    }
  }

  /**
   * 查询余额 (USD)
   * @returns {Promise<number>} 余额
   */
  async getBalance() {
    var r = await this._request("/res.php", { key: this.apiKey, action: "getbalance", json: 1 });
    if (r.status === 1) return parseFloat(r.request) || 0;
    throw new Error("2Captcha getBalance 失败: " + JSON.stringify(r));
  }

  // ========== reCAPTCHA v2 ==========
  /**
   * 解决 reCAPTCHA v2（DrayDog 级稳定，LBCT/EModal 通用）
   * @param {object} p
   * @param {string} p.sitekey   - data-sitekey 属性（如 LBCT: 6LdpmKYUAAAAABfbOneCUYoKkKMzsXv_K0kfLPrA）
   * @param {string} p.pageUrl   - 验证码所在页面的完整 URL
   * @param {boolean} [p.invisible] - 是否是 invisible reCAPTCHA
   * @param {string} [p.userAgent]   - 浏览器 UA，提高通过率
   * @param {string} [p.proxy]       - 格式: login:pass@ip:port (住宅代理 + UA = 通过率接近 100%)
   * @param {string} [p.proxyType]   - http | https | socks4 | socks5
   * @returns {Promise<string>} g-recaptcha-response token (直接塞进表单字段即可)
   */
  async solveRecaptchaV2(p) {
    if (!this.apiKey) throw new Error("2Captcha apiKey 未配置");
    if (!p.sitekey) throw new Error("solveRecaptchaV2: 缺少 sitekey");
    if (!p.pageUrl) throw new Error("solveRecaptchaV2: 缺少 pageUrl");

    var taskParams = {
      key: this.apiKey,
      method: "userrecaptcha",
      googlekey: p.sitekey,
      pageurl: p.pageUrl,
      json: 1
    };
    if (p.invisible) taskParams.invisible = 1;
    if (p.userAgent) taskParams.userAgent = p.userAgent;
    if (p.proxy) { taskParams.proxy = p.proxy; taskParams.proxytype = p.proxyType || "http"; }

    // Step 1: 提交任务，拿到 taskId (captchaId)
    var submit = await this._request("/in.php", taskParams, "POST");
    if (submit.status !== 1 || !submit.request) {
      var errMsg = submit.request || submit.error_text || JSON.stringify(submit);
      throw new Error("2Captcha 提交 reCAPTCHA 失败: " + errMsg);
    }
    var taskId = submit.request;
    console.log("[2Captcha] 任务已提交 taskId=" + taskId + ", sitekey=" + p.sitekey.substring(0, 10) + "...");

    // Step 2: 轮询结果 (官方推荐 5s 一次)
    var startedAt = Date.now();
    while (Date.now() - startedAt < this.maxWaitMs) {
      await sleep(this.pollIntervalMs);
      var result = await this._request("/res.php", {
        key: this.apiKey,
        action: "get",
        id: String(taskId),
        json: 1
      });
      // status=1 成功, status=0 且 request=CAPCHA_NOT_READY 还在处理
      if (result.status === 1) {
        var token = result.request;
        console.log("[2Captcha] 成功，耗时 " + Math.round((Date.now() - startedAt) / 1000) + "s，token 长度=" + token.length);
        // 返回 {taskId, response} 对象，兼容 server.js 的调用方式
        return { taskId: taskId, response: token };
      }
      if (result.request === "CAPCHA_NOT_READY") continue;
      // 其他错误
      throw new Error("2Captcha 解决失败: " + (result.request || JSON.stringify(result)));
    }
    throw new Error("2Captcha 超时 (" + Math.round(this.maxWaitMs / 1000) + "s)，未在规定时间内返回结果");
  }

  // 便捷别名
  async solveRecaptcha(sitekey, pageUrl, extra) {
    return this.solveRecaptchaV2(Object.assign({ sitekey: sitekey, pageUrl: pageUrl }, extra || {}));
  }

  // ========== 报告错误（免费重算，不重复扣费）==========
  /**
   * 报告验证码结果错误（token 被目标网站拒绝）
   * 2Captcha 会退款不扣费，并重新派单（如果余额足够）
   * @param {string} taskId
   */
  async reportBad(taskId) {
    try {
      await this._request("/res.php", { key: this.apiKey, action: "reportbad", id: String(taskId), json: 1 });
    } catch (e) { /* ignore */ }
  }
  /**
   * 报告验证码结果正确（可选，用于提高账号评分）
   */
  async reportGood(taskId) {
    try {
      await this._request("/res.php", { key: this.apiKey, action: "reportgood", id: String(taskId), json: 1 });
    } catch (e) { /* ignore */ }
  }
}

// ========== 导出 (UMD 兼容: CommonJS + ES Module + 浏览器) ==========
if (typeof module !== "undefined" && module.exports) {
  module.exports = { TwoCaptchaClient, sleep };
}
if (typeof window !== "undefined") {
  window.TwoCaptchaClient = TwoCaptchaClient;
  window.sleep = sleep;
}
// ES Module 导出 (Cloudflare Workers 用)
if (typeof exports !== "undefined") {
  exports.TwoCaptchaClient = TwoCaptchaClient;
  exports.sleep = sleep;
}
// @ts-ignore
if (typeof self !== "undefined") {
  // @ts-ignore
  self.TwoCaptchaClient = TwoCaptchaClient;
}
