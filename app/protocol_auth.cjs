'use strict';

// Narrow data-only parser for Web WeChat's login response. No script execution.
const AUTH_HOSTS = new Set(['wx.qq.com', 'wx2.qq.com', 'wx8.qq.com', 'web.wechat.com', 'web2.wechat.com']);
const AUTH_PATH = '/cgi-bin/mmwebwx-bin/webwxnewloginpage';
const FIELDS = { skey: 'skey', sid: 'wxsid', uin: 'wxuin', passTicket: 'pass_ticket' };
function decodeEntities(value) {
  return value.replace(/&(#x[\da-f]+|#\d+|amp|lt|gt|quot|apos);/gi, (full, name) => {
    const named = {amp:'&', lt:'<', gt:'>', quot:'"', apos:"'"};
    if (name[0] !== '#') return named[name.toLowerCase()] || full;
    const code = name[1].toLowerCase() === 'x' ? parseInt(name.slice(2), 16) : Number(name.slice(1));
    return code > 0 && code <= 0x10ffff && !(code >= 0xd800 && code <= 0xdfff) ? String.fromCodePoint(code) : full;
  });
}
function xmlValue(xml, name) {
  const match = xml.match(new RegExp('<' + name + '\\b[^>]*>([\\s\\S]*?)</' + name + '\\s*>', 'i'));
  if (!match) return null;
  // CDATA text must not be interpreted as markup or decoded a second time.
  return match[1].split(/(<!\[CDATA\[[\s\S]*?\]\]>)/).map(part => part.startsWith('<![CDATA[')
    ? part.slice(9, -3) : decodeEntities(part)).join('').trim();
}
function authUrl(value, base) {
  let url;
  try { url = new URL(value, base); } catch { throw new Error('登录跳转地址格式无效'); }
  if (url.protocol !== 'https:' || !AUTH_HOSTS.has(url.hostname) || url.port || url.username || url.password || url.pathname !== AUTH_PATH) {
    throw new Error('登录跳转不是受支持的微信认证地址');
  }
  url.hash = '';
  return url;
}
function reasonFor(message) {
  // Fixed labels only: never persist arbitrary remote text, URLs, or credentials.
  if (/版本过低|版本太低|升级.*微信|最新.*Linux/i.test(message)) return '客户端版本要求不满足';
  if (/不支持.*网页|未.*开放.*网页|无法.*登录.*网页|不能.*登录.*网页|网页版.*不可用/.test(message)) return '服务端提示网页版登录不可用';
  if (/安全|环境异常|风险/.test(message)) return '服务端提示登录安全或环境限制';
  if (/过期|失效|超时/.test(message)) return '服务端提示登录凭据过期';
  if (/频繁|频率/.test(message)) return '服务端提示请求频率限制';
  return message ? '服务端有错误说明，但未匹配已知原因' : '服务端未提供可解析的错误说明';
}
function htmlSummary(body) {
  // Keep only a short redacted visible-text excerpt, never HTML, script, form values or URLs.
  const text = decodeEntities(body.replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<(script|style)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, '')
    .replace(/<(skey|wxsid|wxuin|pass_ticket|ticket|token|uuid)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, '[credential]')
    .replace(/<[^>]*>/g, ' '))
    .replace(/https?:\/\/\S+/gi, '[URL]')
    .replace(/(?:skey|wxsid|wxuin|pass_ticket|ticket|token|uuid|cookie)\s*[:=]\s*\S+/gi, '[credential]')
    .replace(/[A-Za-z0-9_+\/=.%@-]{12,}/g, '[identifier]')
    .replace(/\d{5,}/g, '[number]').replace(/\s+/g, ' ').trim().slice(0, 400);
  return { visible_text: text, reason: reasonFor(text), has_script:/<script\b/i.test(body),
    has_form:/<form\b/i.test(body), has_meta_refresh:/<meta\b[^>]*http-equiv\s*=\s*["']?refresh/i.test(body) };
}
function analyzeAuthResponse(response) {
  const body = typeof response.data === 'string' ? response.data : '';
  const retValue = xmlValue(body, 'ret');
  const ret = retValue !== null && /^-?\d{1,9}$/.test(retValue) ? Number(retValue) : null;
  const message = xmlValue(body, 'message') || '';
  const credentials = Object.fromEntries(Object.entries(FIELDS).map(([key, tag]) => [key, xmlValue(body, tag) || '']));
  const contentType = String(response.headers?.['content-type'] || '').split(';')[0];
  const diagnostic = {
    http_status: Number(response.status) || 0,
    content_type: /^[a-z0-9.+-]+\/[a-z0-9.+-]+$/i.test(contentType) ? contentType : 'unknown',
    response_kind: typeof response.data !== 'string' ? 'non_text' : /<html\b/i.test(body) ? 'html' : /<error\b/i.test(body) ? 'xml' : 'other',
    body_bytes: Buffer.byteLength(body), ret,
    has_cdata: body.includes('<![CDATA['), has_message: Boolean(message),
    credential_fields: Object.keys(credentials).filter(key => Boolean(credentials[key])),
  };
  if (diagnostic.response_kind === 'html') diagnostic.html = htmlSummary(body);
  if (ret !== null && ret !== 0) return { kind:'rejected', diagnostic:{...diagnostic, reason:reasonFor(message)} };
  if (ret === 0 && Object.values(credentials).every(Boolean) && [200, 301, 302, 303, 307, 308].includes(diagnostic.http_status)) {
    return { kind:'authenticated', diagnostic, credentials };
  }
  const redirect = xmlValue(body, 'redirecturl') || ([301,302,303,307,308].includes(diagnostic.http_status) ? response.headers?.location : null);
  if (redirect) return { kind:'redirect', diagnostic, redirect };
  return { kind: ret === 0 ? 'missing_credentials' : 'unrecognized', diagnostic };
}
async function fetchAuth(request, redirect, report, getCookies = () => ({})) {
  let originalUrl = authUrl(redirect), url = new URL(originalUrl), mode = 'xhr', usedHtmlFallback = false;
  const visited = new Set();
  for (let hop = 0; hop < 4; hop++) {
    if (mode === 'xhr') { url.searchParams.set('fun', 'new'); url.searchParams.set('version', 'v2'); }
    if (visited.has(url.href)) throw new Error('微信登录跳转循环，已停止');
    visited.add(url.href);
    const response = await request({ method:'GET', url:url.href, maxRedirects:0,
      headers:{ Referer:url.origin + '/', Accept:mode === 'document' ? 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' : 'application/xml,text/xml,text/html;q=0.9,*/*;q=0.8' },
      validateStatus: () => true });
    const result = analyzeAuthResponse(response);
    const cookies = getCookies();
    const cookieFields = ['wxsid','wxuin','skey','pass_ticket'].filter(key => typeof cookies[key] === 'string' && cookies[key]);
    report({ ...result.diagnostic, outcome:result.kind, hop, request_mode:mode, auth_host:url.hostname, cookie_fields:cookieFields });
    if (result.kind === 'authenticated') return { credentials:result.credentials, hostname:url.hostname };
    if (result.kind === 'rejected') throw new Error('微信明确拒绝登录（ret=' + result.diagnostic.ret + '）：' + result.diagnostic.reason);
    if (result.kind === 'redirect') { originalUrl = authUrl(result.redirect, url); url = new URL(originalUrl); mode = 'xhr'; continue; }
    // The official accountFactory reads wxsid/wxuin from cookies and permits an empty
    // Skey before webwxinit. These are only candidates: init must validate the session.
    if (response.status === 200 && typeof cookies.wxsid === 'string' && cookies.wxsid && /^\d{1,20}$/.test(cookies.wxuin || '') &&
        (result.diagnostic.response_kind === 'html' || result.kind === 'missing_credentials')) {
      report({ outcome:'cookie_session_candidate', hop, auth_host:url.hostname, cookie_fields:cookieFields });
      return { hostname:url.hostname, requiresInit:true, credentials:{sid:cookies.wxsid, uin:cookies.wxuin, skey:cookies.skey || '', passTicket:cookies.pass_ticket || ''} };
    }
    if (result.kind === 'missing_credentials') throw new Error('微信返回 ret=0，但登录凭据不完整；不能确认登录成功');
    // wx.qq.com's public client navigates to the original redirect_uri when its XHR
    // returns an HTML document. Reproduce that GET once, without executing HTML/JS.
    if (!usedHtmlFallback && response.status === 200 && result.diagnostic.response_kind === 'html' && /<head\b/i.test(response.data) && !visited.has(originalUrl.href)) {
      usedHtmlFallback = true; mode = 'document'; url = new URL(originalUrl); continue;
    }
    throw new Error('登录响应未识别（HTTP ' + result.diagnostic.http_status + '，' + result.diagnostic.response_kind + '，未取得有效 ret）；不能据此判断账号权限');
  }
  throw new Error('微信登录跳转次数过多，已停止');
}
module.exports = { xmlValue, authUrl, analyzeAuthResponse, fetchAuth, htmlSummary };
