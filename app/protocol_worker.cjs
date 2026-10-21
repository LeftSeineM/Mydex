'use strict';
// Headless Web WeChat transport. No desktop APIs, browser driver, or OpenClaw.
const path = require('node:path');
const readline = require('node:readline');
const fs = require('node:fs');
const { fetchAuth } = require('./protocol_auth.cjs');
const authDiagnostics = [];
function recordAuthDiagnostic(record) {
  authDiagnostics.push({ recorded_at: new Date().toISOString(), ...record });
  const folder = path.join(__dirname, '.local');
  fs.mkdirSync(folder, { recursive: true });
  fs.writeFileSync(path.join(folder, 'protocol-diagnostic.json'), JSON.stringify({ version: 1, attempts: authDiagnostics }, null, 2), 'utf8');
}
const dependencyRoot = process.env.WECHAT_LAB_PROTOCOL_DIR || path.join(process.env.MYDEX_RUNTIME_DIR || path.join(__dirname, '..', '.runtime'), 'protocol', 'node_modules');
let bot, getCONF;
function initializeTransport() {
const Core = require(path.join(dependencyRoot, 'wechat4u/lib/core')).default;
({ getCONF } = require(path.join(dependencyRoot, 'wechat4u/lib/util/conf')));
bot = new Core();
const request = bot.request;
bot.request = async options => {
  const response = await request({ ...options, timeout: 35000, maxRedirects: 0 });
  if (new URL(options.url).pathname === '/cgi-bin/mmwebwx-bin/webwxinit') {
    const data = response.data;
    recordAuthDiagnostic({ stage:'initialization', http_status:response.status,
      ret:Number.isInteger(data?.BaseResponse?.Ret) ? data.BaseResponse.Ret : null,
      has_user:Boolean(data?.User?.UserName), has_sync_key:Array.isArray(data?.SyncKey?.List) });
  }
  return response;
};
}
const emit = event => process.stdout.write(JSON.stringify(event) + '\n');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const decode = s => String(s || '').replace(/<br\s*\/?\s*>/gi, '\n').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&');
let active = false, target = null, settings = null, startedAt = 0;
const rooms = new Map(), sentIds = new Set();
const safeError = e => e.publicMessage || ('协议请求失败：' + (e.code || e.response?.status || e.name || 'unknown'));
function failure(text) { const e = new Error(text); e.publicMessage = text; return e; }
function webLoginUrl(conf) {
  // Match wx.qq.com's public web client, not the dependency's legacy desktop/UOS route.
  const url = new URL(conf.API_jsLogin);
  url.searchParams.set('redirect_uri', conf.origin + '/cgi-bin/mmwebwx-bin/webwxnewloginpage');
  url.searchParams.set('lang', 'zh_CN');
  return url.toString();
}
function parseQrResponse(body) {
  const code = String(body).match(/QRLogin\.code\s*=\s*(\d+)/)?.[1];
  const uuid = String(body).match(/QRLogin\.uuid\s*=\s*["']([\w=-]+)["']/)?.[1];
  if (code !== '200' || !uuid) throw failure('微信未返回有效登录二维码，网页版协议入口不可用');
  return uuid;
}
function parseSyncResponse(body) {
  const value = String(body), ret = value.match(/retcode\s*:\s*"(\d+)"/)?.[1], selector = value.match(/selector\s*:\s*"(\d+)"/)?.[1];
  if (ret !== '0' || selector === undefined) throw failure('微信同步已停止（状态 ' + (ret || '未知') + '），请重新扫码');
  return selector;
}
function pickRoom(list, name) {
  const matches = list.filter(c => c.UserName?.startsWith('@@') && decode(c.NickName) === name);
  if (matches.length > 1) throw failure('存在同名群，无法唯一确定目标；请给测试群设置唯一名称后重连');
  return matches[0] || null;
}
function phase(value, message, extra = {}) { emit({ type: 'status', phase: value, message, ...extra }); }
function updateRooms(list = []) {
  for (const c of list) if (c.UserName?.startsWith('@@')) rooms.set(c.UserName, { ...rooms.get(c.UserName), ...c });
}
function selectTarget() {
  target = pickRoom([...rooms.values()], settings.group);
  return target;
}
async function login() {
  phase('connecting', '正在请求微信网页版登录二维码…');
  const res = await bot.request({ method: 'GET', url: webLoginUrl(bot.CONF) });
  const uuid = parseQrResponse(res.data);
  bot.PROP.uuid = uuid;
  const qr = await bot.request({ method: 'GET', url: 'https://login.weixin.qq.com/qrcode/' + uuid, responseType: 'arraybuffer' });
  const bytes = Buffer.from(qr.data);
  if (bytes.length > 512000 || !String(qr.headers['content-type']).startsWith('image/')) throw failure('二维码响应格式无效');
  emit({ type: 'qr', data: bytes.toString('base64'), mime: qr.headers['content-type'].split(';')[0], expires_at: Date.now()/1000 + 180 });
  phase('waiting_scan', '请用准备充当助手的微信账号扫码，并在手机上确认登录');
  const deadline = Date.now() + 180000;
  while (active && Date.now() < deadline) {
    const check = await bot.request({ method: 'GET', url: bot.CONF.API_login, params: { uuid, tip: 0, r: ~Date.now() } });
    const text = String(check.data), status = Number(text.match(/window\.code\s*=\s*(\d+)/)?.[1]);
    if (status === 201) phase('waiting_confirm', '二维码已扫描，请在手机微信确认登录');
    if (status === 400) throw failure('二维码已失效，请点击重新扫码');
    if (status === 200) {
      const redirect = text.match(/window\.redirect_uri\s*=\s*["']([^"']+)["']/)?.[1];
      phase('authenticating', '手机已确认，正在核对微信登录返回码…', { logged_in: false });
      let auth;
      try { auth = await fetchAuth(bot.request, redirect, recordAuthDiagnostic, () => bot.COOKIE); }
      catch (error) {
        // Network errors may contain request credentials; expose only our own parser errors.
        if (error.response || error.config || error.code) throw error;
        throw failure(error.message);
      }
      bot.CONF = getCONF(auth.hostname);
      Object.assign(bot.PROP, auth.credentials);
      emit({ type: 'clear_qr' });
      return;
    }
    if (![200,201,408].includes(status)) throw failure('微信登录状态异常：' + status);
    await delay(1000);
  }
  throw failure('二维码等待超时，请点击重新扫码');
}
async function syncCheck() {
  const res = await bot.request({ method: 'GET', url: bot.CONF.API_synccheck, params: { r: Date.now(), sid: bot.PROP.sid, uin: bot.PROP.uin, skey: bot.PROP.skey, deviceid: bot.getBaseRequest().DeviceID, synckey: bot.PROP.formatedSyncKey } });
  return parseSyncResponse(res.data);
}
async function announceTarget() {
  if (!selectTarget()) return phase('waiting_group', '微信协议已登录；未找到「' + settings.group + '」。建群后请让群成员发一条消息。', { logged_in: true });
  const details = await bot.batchGetContact([{ UserName: target.UserName }]);
  updateRooms(details); selectTarget();
  const self = target.MemberList?.find(m => m.UserName === bot.user.UserName);
  phase('listening', '已通过消息协议连接目标群，等待新消息；没有使用屏幕操控', { logged_in: true, account_name: decode(bot.user.NickName), mention_name: decode(self?.DisplayName || self?.NickName || bot.user.NickName) });
}
async function run(config) {
  settings = config; active = true;
  await login(); if (!active) return;
  phase('initializing', '微信已返回登录凭据，正在验证会话并定位测试群…', { logged_in: false });
  const init = await bot.init();
  if (!init.User?.UserName || !Array.isArray(init.SyncKey?.List)) throw failure('微信初始化响应不完整；会话尚未验证成功');
  updateRooms(init.ContactList);
  let seq = 0;
  do { const page = await bot.getContact(seq); updateRooms(page.MemberList); seq = page.Seq || 0; } while (active && seq);
  // Initial sync is a baseline; never replay messages predating this connection.
  const baseline = await bot.sync(); updateRooms(baseline.ModContactList);
  startedAt = Math.floor(Date.now()/1000);
  await announceTarget();
  while (active) {
    if (await syncCheck() !== '0') {
      const data = await bot.sync(); updateRooms(data.ModContactList);
      for (const contact of data.DelContactList || []) rooms.delete(contact.UserName);
      const previousId = target?.UserName;
      selectTarget();
      if (target && !previousId) await announceTarget();
      for (const msg of data.AddMsgList || []) {
        if (!active || +msg.MsgType !== 1 || !msg.FromUserName?.startsWith('@@') || +msg.CreateTime < startedAt) continue;
        if (!rooms.has(msg.FromUserName)) { updateRooms(await bot.batchGetContact([{ UserName: msg.FromUserName }])); selectTarget(); if(target && !previousId) await announceTarget(); }
        if (!target || msg.FromUserName !== target.UserName) continue;
        const raw = decode(msg.Content), split = raw.match(/^(@[^:\n]+):\n([\s\S]*)$/);
        if (!split || split[1] === bot.user.UserName) continue;
        const member = target.MemberList?.find(m => m.UserName === split[1]);
        const self = target.MemberList?.find(m => m.UserName === bot.user.UserName);
        const actualMention = decode(self?.DisplayName || self?.NickName || bot.user.NickName);
        let content = split[2];
        // Normalize only the authenticated account's own mention to the configured assistant alias.
        if (actualMention && actualMention !== settings.bot_name) content = content.replace('@' + actualMention + '\u2005', '@' + settings.bot_name + '\u2005');
        const escaped = settings.bot_name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        if (!new RegExp('@' + escaped + '(?=$|\\s|[，,:：。!?！？])').test(content)) continue;
        emit({ type: 'message', id: String(msg.MsgId), room: settings.group, room_id: target.UserName, sender: decode(member?.DisplayName || member?.NickName || '群成员'), content });
      }
    }
    await delay(1000);
  }
}
if (require.main === module) {
initializeTransport();
readline.createInterface({ input: process.stdin }).on('line', line => {
  let cmd; try { cmd = JSON.parse(line); } catch { return; }
  if (cmd.type === 'start' && !active) run(cmd).catch(e => { phase('error', safeError(e), { logged_in: false }); active = false; process.exitCode = 1; process.stdin.destroy(); });
  if (cmd.type === 'stop') { active = false; process.exit(0); }
  if (cmd.type === 'send') {
    if (!active || !target || cmd.room_id !== target.UserName || decode(target.NickName) !== settings.group || sentIds.has(cmd.id)) return emit({ type: 'sent', id: cmd.id, ok: false });
    sentIds.add(cmd.id);
    bot.sendText(String(cmd.content).slice(0,4000), target.UserName).then(() => emit({ type: 'sent', id: cmd.id, ok: true })).catch(() => emit({ type: 'sent', id: cmd.id, ok: false }));
  }
});
process.stdin.on('end', () => { active = false; process.exit(0); });
}
module.exports = { parseQrResponse, parseSyncResponse, pickRoom, webLoginUrl };
