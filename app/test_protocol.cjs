const { test } = require('node:test');
const assert = require('node:assert/strict');
const { parseQrResponse, parseSyncResponse, pickRoom, webLoginUrl } = require('./protocol_worker.cjs');
const { xmlValue, analyzeAuthResponse, fetchAuth } = require('./protocol_auth.cjs');
const loginXml = '<error><ret>0</ret><skey>secret-skey</skey><wxsid>secret-sid</wxsid><wxuin>123456789</wxuin><pass_ticket>secret-ticket</pass_ticket></error>';
const response = (data, status=200, headers={}) => ({data, status, headers});
test('CDATA and XML entities preserve login values without executing content', () => {
  assert.equal(xmlValue('<message><![CDATA[暂时无法登录网页版微信]]></message>', 'message'), '暂时无法登录网页版微信');
  assert.equal(xmlValue('<skey> a&amp;b&#61;&#x3d; </skey>', 'skey'), 'a&b==');
  assert.equal(xmlValue('<skey><![CDATA[a&amp;b]]></skey>', 'skey'), 'a&amp;b');
});
test('explicit rejection retains numeric return code and a fixed reason label', () => {
  const result = analyzeAuthResponse(response('<error><ret>1203</ret><message><![CDATA[暂时无法登录网页版微信 https://wx.qq.com/?ticket=SECRET-TICKET]]></message></error>'));
  assert.equal(result.kind, 'rejected');
  assert.equal(result.diagnostic.ret, 1203);
  assert.equal(result.diagnostic.reason, '服务端提示网页版登录不可用');
  assert.equal(JSON.stringify(result).includes('SECRET-TICKET'), false);
});
test('HTML, empty responses and JSON are not mislabeled as account rejection', () => {
  for (const body of ['<html><head></head><body>redirect</body></html>', '', {ret:0}]) {
    const result = analyzeAuthResponse(response(body));
    assert.equal(result.kind, 'unrecognized');
    assert.equal(result.diagnostic.ret, null);
  }
});
test('success requires all credentials and diagnostics contain only field names', () => {
  const result = analyzeAuthResponse(response(loginXml, 301));
  assert.equal(result.kind, 'authenticated');
  assert.equal(result.credentials.sid, 'secret-sid');
  assert.equal(JSON.stringify(result.diagnostic).includes('secret'), false);
  assert.equal(JSON.stringify(result.diagnostic).includes('123456789'), false);
  assert.equal(analyzeAuthResponse(response('<error><ret>0</ret></error>')).kind, 'missing_credentials');
});
test('official auth redirects are followed explicitly and capped, not executed', async () => {
  const calls=[], diagnostics=[];
  const result = await fetchAuth(async options => {
    calls.push(options);
    return calls.length === 1 ? response('', 302, {location:'https://wx2.qq.com/cgi-bin/mmwebwx-bin/webwxnewloginpage?ticket=secret'}) : response(loginXml);
  }, 'https://wx.qq.com/cgi-bin/mmwebwx-bin/webwxnewloginpage?ticket=initial', d => diagnostics.push(d));
  assert.equal(result.hostname, 'wx2.qq.com');
  assert.equal(calls.length, 2);
  assert.equal(calls[0].maxRedirects, 0);
  assert.equal(JSON.stringify(diagnostics).includes('secret'), false);
  assert.equal(JSON.stringify(diagnostics).includes('initial'), false);
});
test('redirects to other hosts or non-auth paths are rejected before any follow-up', async () => {
  for (const location of ['https://evil.invalid/login', 'http://wx.qq.com/cgi-bin/mmwebwx-bin/webwxnewloginpage', 'https://wx.qq.com/', 'https://wx.qq.com:444/cgi-bin/mmwebwx-bin/webwxnewloginpage']) {
    let calls=0;
    await assert.rejects(fetchAuth(async () => {calls++; return response('', 302, {location});}, 'https://wx.qq.com/cgi-bin/mmwebwx-bin/webwxnewloginpage', () => {}), /受支持/);
    assert.equal(calls, 1);
  }
});
test('a redirect loop stops and does not repeat the login request', async () => {
  let calls=0;
  await assert.rejects(fetchAuth(async () => {calls++; return response('', 302, {location:'https://wx.qq.com/cgi-bin/mmwebwx-bin/webwxnewloginpage'});}, 'https://wx.qq.com/cgi-bin/mmwebwx-bin/webwxnewloginpage', () => {}), /循环/);
  assert.equal(calls, 1);
});
test('HTML fallback follows the official original-URL GET once without XHR parameters', async () => {
  const calls=[], diagnostics=[];
  const result = await fetchAuth(async options => {
    calls.push(new URL(options.url));
    return calls.length === 1 ? response('<html><head></head><body>redirect</body></html>') : response(loginXml);
  }, 'https://wx.qq.com/cgi-bin/mmwebwx-bin/webwxnewloginpage?ticket=secret', d => diagnostics.push(d));
  assert.equal(result.credentials.sid, 'secret-sid');
  assert.equal(calls[0].searchParams.get('fun'), 'new');
  assert.equal(calls[1].searchParams.has('fun'), false);
  assert.equal(calls[1].searchParams.get('ticket'), 'secret');
  assert.equal(diagnostics[1].request_mode, 'document');
});
test('repeated HTML stops after a single fallback and never counts as login', async () => {
  let calls=0;
  await assert.rejects(fetchAuth(async () => {calls++; return response('<html><head></head><body>需要验证</body></html>');}, 'https://wx.qq.com/cgi-bin/mmwebwx-bin/webwxnewloginpage', () => {}), /未识别/);
  assert.equal(calls, 2);
});
test('HTML diagnostics omit scripts, form values, identifiers and credential URLs', () => {
  const result = analyzeAuthResponse(response('<html><head><script>ticket="top-secret";globalThis.htmlExecuted=true</script><style>SECRET_STYLE</style></head><body>登录环境异常 <input value="secret-input"><skey>shortsecret</skey>账号123456789 token=secret-token https://wx.qq.com/?ticket=secret-url</body></html>'));
  assert.equal(result.diagnostic.html.reason, '服务端提示登录安全或环境限制');
  for (const secret of ['top-secret','SECRET_STYLE','secret-input','shortsecret','123456789','secret-token','secret-url']) assert.equal(JSON.stringify(result).includes(secret), false);
  assert.equal(globalThis.htmlExecuted, undefined);
});
test('HTML with fresh session cookies proceeds only as an initialization candidate', async () => {
  const diagnostics=[];
  const result = await fetchAuth(async () => response('<html><head></head><body>微信</body></html>'),
    'https://wx.qq.com/cgi-bin/mmwebwx-bin/webwxnewloginpage', d => diagnostics.push(d), () => ({wxsid:'secret-sid',wxuin:'123456789'}));
  assert.equal(result.requiresInit, true);
  assert.equal(result.credentials.sid, 'secret-sid');
  assert.equal(result.credentials.skey, '');
  for (const secret of ['secret-sid','123456789']) assert.equal(JSON.stringify(diagnostics).includes(secret), false);
});
test('explicit rejection takes precedence over any session cookies', async () => {
  await assert.rejects(fetchAuth(async () => response('<error><ret>1203</ret></error>'),
    'https://wx.qq.com/cgi-bin/mmwebwx-bin/webwxnewloginpage', () => {}, () => ({wxsid:'secret-sid',wxuin:'123456789'})), /明确拒绝/);
});
test('web login uses an encoded web callback without legacy desktop mode', () => {
  const url = new URL(webLoginUrl({origin:'https://wx.qq.com',API_jsLogin:'https://login.wx.qq.com/jslogin?appid=wx782c26e4c19acffb&redirect_uri=https://wx.qq.com/cgi-bin/mmwebwx-bin/webwxnewloginpage?mod=desktop&fun=new'}));
  assert.equal(url.searchParams.get('appid'), 'wx782c26e4c19acffb');
  assert.equal(url.searchParams.get('redirect_uri'), 'https://wx.qq.com/cgi-bin/mmwebwx-bin/webwxnewloginpage');
  assert.equal(url.searchParams.get('lang'), 'zh_CN');
  assert.equal(url.toString().includes('desktop'), false);
});
test('QR responses are parsed as data and never executed', () => {
  const payload = 'window.QRLogin.code = 200; window.QRLogin.uuid = "abc-123="; globalThis.protocolTestExecuted=true';
  assert.equal(parseQrResponse(payload), 'abc-123=');
  assert.equal(globalThis.protocolTestExecuted, undefined);
  assert.throws(() => parseQrResponse('window.QRLogin.code=400;'));
});
test('invalid and logged-out sync responses fail closed', () => {
  assert.equal(parseSyncResponse('window.synccheck={retcode:"0",selector:"2"}'), '2');
  assert.throws(() => parseSyncResponse('window.synccheck={retcode:"1100",selector:"0"}'));
  assert.throws(() => parseSyncResponse('<html>login required</html>'));
});
test('only exact group names qualify, never a similarly named contact', () => {
  const list = [{UserName:'@friend',NickName:'Mydex测试群'}, {UserName:'@@room',NickName:'Mydex测试群'}];
  assert.equal(pickRoom(list, 'Mydex测试群').UserName, '@@room');
  assert.equal(pickRoom(list, 'Mydex测试群二号'), null);
});
test('duplicate group names cannot choose a send target', () => {
  assert.throws(() => pickRoom([{UserName:'@@a',NickName:'test'},{UserName:'@@b',NickName:'test'}], 'test'));
});
