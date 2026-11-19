// R-6 threads UI battery: chip, main-pane thread view, follow toggle,
// live arrival (dot + open pane), reply edit/delete in the pane,
// search-into-thread, notification-into-thread, instance overlay.
const puppeteer = require('puppeteer-core');

const BASE = process.env.ATRIUM_BASE || 'http://127.0.0.1:5080';
const SHOTS = process.env.SHOTS_DIR || '.';
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
let pass = 0, fail = 0;
const check = (name, ok) => { ok ? pass++ : fail++; console.log((ok ? 'PASS ' : 'FAIL ') + name); };

async function apiLogin(user, pw) {
  const res = await fetch(BASE + '/api/auth/login', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: user, password: pw }),
  });
  return res.headers.getSetCookie().map(c => c.split(';')[0]).join('; ');
}
async function api(cookie, method, path, body) {
  const res = await fetch(BASE + path, {
    method, headers: { 'Content-Type': 'application/json', 'Cookie': cookie },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  try { return { status: res.status, json: JSON.parse(text) }; }
  catch { return { status: res.status, json: null }; }
}
const guid = () => crypto.randomUUID();

(async () => {
  // ---- seed via API: jdoe root, asmith reply (auto-follow) ----
  const jdoe = await apiLogin('jdoe', 'Password!2026');
  const asmithApi = await apiLogin('asmith', 'Password!2026');
  const root = await api(jdoe, 'POST', '/api/channels/1/messages',
    { body: 'ui thread root', clientGuid: guid() });
  const rootId = root.json.id, rootSeq = root.json.seq;
  await api(asmithApi, 'POST', '/api/channels/1/messages',
    { body: 'ui reply one', clientGuid: guid(), parentId: rootId });

  const browser = await puppeteer.launch({
    executablePath: process.env.CHROME_PATH,
    headless: 'new', args: ['--no-sandbox', '--window-size=1600,1000'],
  });
  const page = await browser.newPage();
  await page.setViewport({ width: 1600, height: 1000 });

  const signIn = async (user, pw) => {
    await page.goto(BASE, { waitUntil: 'networkidle2', timeout: 60000 });
    await page.waitForSelector('.login-card', { timeout: 30000 });
    const ins = await page.$$('.login-card input');
    await ins[0].type(user);
    await ins[1].type(pw);
    await page.evaluate(() => [...document.querySelectorAll('.login-card button')].find(b => b.textContent.includes('Sign in')).click());
    await page.waitForSelector('.mm-shell', { timeout: 30000 });
    await sleep(1200);
  };
  const typeIn = async (selector, text) => {
    await page.evaluate((sel, t) => {
      const el = document.querySelector(sel);
      el.focus();
      const setter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value').set;
      setter.call(el, t);
      el.dispatchEvent(new Event('input', { bubbles: true }));
    }, selector, text);
    await sleep(250);
  };
  const pressEnter = async (selector) => {
    await page.focus(selector);
    await page.keyboard.press('Enter');
    await sleep(700);
  };
  const rowWith = (text) => page.evaluateHandle((t) =>
    [...document.querySelectorAll('.mm-body > .chat-pane .message-row')].filter(r => r.textContent.includes(t)).pop(), text);
  // NOTE: every row lookup below uses the LAST match — earlier battery
  // runs seeded identical texts, and the newest root is the live one.

  await signIn('asmith', 'Password!2026');
  // open #general
  await page.evaluate(() => [...document.querySelectorAll('.channel-row')]
    .find(e => e.textContent.includes('general'))?.click());
  await sleep(800);
  const inGeneral = await page.evaluate((rs) =>
    [...document.querySelectorAll('.mm-body > .chat-pane .message-row')].some(r => r.textContent.includes('ui thread root')), rootSeq);
  check('root message visible in #general', inGeneral);

  // ---- chip ----
  const chip = await page.evaluate(() => {
    const row = [...document.querySelectorAll('.mm-body > .chat-pane .message-row')].filter(r => r.textContent.includes('ui thread root')).pop();
    const c = row?.querySelector('.thread-chip');
    return c ? { text: c.textContent.trim(), dot: !!c.querySelector('.thread-dot'), box: !!c.getBoundingClientRect().width } : null;
  });
  check('thread chip shows 1 reply', !!chip && /1 reply/.test(chip.text) && chip.box, JSON.stringify(chip));
  check('chip has no unread dot for the replier', !!chip && !chip.dot);
  await page.screenshot({ path: SHOTS + '/ui11-01-chip.png' });

  // ---- open the thread pane via Reply ----
  const row = await rowWith('ui thread root');
  await row.hover();
  await sleep(300);
  await page.evaluate(() => {
    const r = [...document.querySelectorAll('.mm-body > .chat-pane .message-row')].filter(x => x.textContent.includes('ui thread root')).pop();
    [...r.querySelectorAll('.msg-action')].find(b => b.textContent.trim() === 'Reply')?.click();
  });
  await page.waitForSelector('.thread-rhs', { timeout: 10000 });
  await sleep(600);
  const pane = await page.evaluate(() => ({
    root: (document.querySelector('.thread-rhs .message-row')?.textContent || '').includes('ui thread root'),
    replies: [...document.querySelectorAll('.thread-rhs .message-row')].map(r => r.textContent),
    follow: [...document.querySelectorAll('.thread-rhs .rhs-head button')].map(b => b.textContent.trim()),
  }));
  check('thread pane opens with root + reply', pane.root && pane.replies.some(t => t.includes('ui reply one')));
  check('pane shows Following (auto-follow on reply)', pane.follow.includes('Following'), JSON.stringify(pane.follow));
  await page.screenshot({ path: SHOTS + '/ui11-02-thread-pane.png' });

  // ---- send a reply from the pane ----
  await typeIn('.thread-rhs .thread-composer textarea', 'ui reply two');
  await pressEnter('.thread-rhs .thread-composer textarea');
  const gotTwo = await page.evaluate(() =>
    [...document.querySelectorAll('.thread-rhs .message-row')].some(r => r.textContent.includes('ui reply two')));
  check('pane composer sends a reply that renders', gotTwo);
  const chip2 = await page.evaluate(() => {
    const row = [...document.querySelectorAll('.mm-body > .chat-pane .message-row')].filter(r => r.textContent.includes('ui thread root')).pop();
    return row?.querySelector('.thread-chip')?.textContent.trim();
  });
  check('chip count bumps to 2 replies', /2 replies/.test(chip2 || ''), chip2);

  // ---- follow toggle ----
  await page.evaluate(() => [...document.querySelectorAll('.thread-rhs .rhs-head button')]
    .find(b => b.textContent.trim() === 'Following')?.click());
  await sleep(500);
  const followOff = await page.evaluate(() => [...document.querySelectorAll('.thread-rhs .rhs-head button')]
    .some(b => b.textContent.trim() === 'Follow'));
  check('follow toggle off', followOff);
  await page.evaluate(() => [...document.querySelectorAll('.thread-rhs .rhs-head button')]
    .find(b => b.textContent.trim() === 'Follow')?.click());
  await sleep(500);

  // ---- close pane; live reply raises the dot ----
  await page.evaluate(() => document.querySelector('.thread-rhs .rhs-head .mud-icon-button')?.click());
  await sleep(400);
  check('pane closes', await page.evaluate(() => !document.querySelector('.thread-rhs')));
  await api(jdoe, 'POST', '/api/channels/1/messages',
    { body: 'ui reply three', clientGuid: guid(), parentId: rootId });
  await sleep(1200);
  const dot = await page.evaluate(() => {
    const row = [...document.querySelectorAll('.mm-body > .chat-pane .message-row')].filter(r => r.textContent.includes('ui thread root')).pop();
    const c = row?.querySelector('.thread-chip');
    return c ? { dot: !!c.querySelector('.thread-dot'), text: c.textContent.trim() } : null;
  });
  check('live reply bumps chip to 3 with unread dot', !!dot && dot.dot && /3 replies/.test(dot.text), JSON.stringify(dot));

  // ---- reopen: reply present, dot cleared; live reply lands in open pane ----
  await page.evaluate(() => {
    const r = [...document.querySelectorAll('.mm-body > .chat-pane .message-row')].filter(x => x.textContent.includes('ui thread root')).pop();
    r.querySelector('.thread-chip')?.click();
  });
  await page.waitForSelector('.thread-rhs', { timeout: 10000 });
  await sleep(600);
  const three = await page.evaluate(() =>
    [...document.querySelectorAll('.thread-rhs .message-row')].some(r => r.textContent.includes('ui reply three')));
  check('reopened thread shows the live reply', three);
  const dotGone = await page.evaluate(() => {
    const row = [...document.querySelectorAll('.mm-body > .chat-pane .message-row')].filter(r => r.textContent.includes('ui thread root')).pop();
    return !row?.querySelector('.thread-chip .thread-dot');
  });
  check('opening the thread clears the dot', dotGone);
  await api(jdoe, 'POST', '/api/channels/1/messages',
    { body: 'ui reply four', clientGuid: guid(), parentId: rootId });
  await sleep(1200);
  const four = await page.evaluate(() =>
    [...document.querySelectorAll('.thread-rhs .message-row')].some(r => r.textContent.includes('ui reply four')));
  check('live reply lands in the open pane', four);

  // ---- edit + delete own reply in the pane ----
  await page.evaluate(() => {
    const r = [...document.querySelectorAll('.thread-rhs .message-row')].find(x => x.textContent.includes('ui reply two'));
    r.scrollIntoView();
  });
  await sleep(300);
  const paneRow = await page.evaluateHandle(() =>
    [...document.querySelectorAll('.thread-rhs .message-row')].find(x => x.textContent.includes('ui reply two')));
  await paneRow.hover();
  await sleep(300);
  await page.evaluate(() => {
    const r = [...document.querySelectorAll('.thread-rhs .message-row')].find(x => x.textContent.includes('ui reply two'));
    [...r.querySelectorAll('.msg-action')].find(b => b.textContent.trim() === 'Edit')?.click();
  });
  await sleep(400);
  await typeIn('.thread-rhs .edit-input', 'ui reply two edited');
  await page.evaluate(() => [...document.querySelectorAll('.thread-rhs .edit-actions button')]
    .find(b => b.textContent.trim() === 'Save')?.click());
  await sleep(700);
  check('reply edit in pane saves', await page.evaluate(() =>
    [...document.querySelectorAll('.thread-rhs .message-row')].some(r => r.textContent.includes('ui reply two edited'))));
  const delRow = await page.evaluateHandle(() =>
    [...document.querySelectorAll('.thread-rhs .message-row')].find(x => x.textContent.includes('ui reply two edited')));
  await delRow.hover();
  await sleep(300);
  await page.evaluate(() => {
    const r = [...document.querySelectorAll('.thread-rhs .message-row')].find(x => x.textContent.includes('ui reply two edited'));
    [...r.querySelectorAll('.msg-action')].find(b => b.textContent.trim() === 'Delete')?.click();
  });
  await sleep(300);
  await page.evaluate(() => {
    const r = [...document.querySelectorAll('.thread-rhs .message-row')].find(x => x.textContent.includes('ui reply two edited'));
    [...r.querySelectorAll('.msg-action')].find(b => b.textContent.trim() === 'Confirm delete')?.click();
  });
  await sleep(700);
  check('reply delete in pane removes the row', await page.evaluate(() =>
    ![...document.querySelectorAll('.thread-rhs .message-row')].some(r => r.textContent.includes('ui reply two'))));

  // ---- search result opens the thread ----
  await page.evaluate(() => document.querySelector('.thread-rhs .rhs-head .mud-icon-button')?.click());
  await sleep(300);
  const searchInput = await page.$('.gh-center input, .mm-global-header input');
  await searchInput.click();
  await page.evaluate(() => {
    const el = document.querySelector('.gh-center input, .mm-global-header input');
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
    setter.call(el, 'ui reply four');
    el.dispatchEvent(new Event('input', { bubbles: true }));
  });
  await page.waitForSelector('.search-row', { timeout: 10000 });
  await sleep(400);
  await page.evaluate(() => document.querySelector('.search-row')?.click());
  await page.waitForSelector('.thread-rhs', { timeout: 10000 });
  await sleep(700);
  const hl = await page.evaluate(() =>
    [...document.querySelectorAll('.thread-rhs .message-row')].some(r => r.classList.contains('highlight') && r.textContent.includes('ui reply four')));
  check('search result opens the thread with the reply highlighted', hl);

  // ---- notification opens the thread ----
  await page.evaluate(() => document.querySelector('.thread-rhs .rhs-head .mud-icon-button')?.click());
  await sleep(300);
  await api(jdoe, 'POST', '/api/channels/1/messages',
    { body: 'ui reply five', clientGuid: guid(), parentId: rootId });
  await sleep(1200);
  await page.evaluate(() => document.querySelector('.bell-btn, [title="Notifications"]')?.click());
  await sleep(800);
  const notif = await page.evaluate(() => {
    const rows = [...document.querySelectorAll('.notif-row, .notif-item')];
    const hit = rows.find(r => r.textContent.includes('replied in a thread'));
    return hit ? hit.textContent.trim().slice(0, 80) : null;
  });
  check('action center shows the thread reply notification', !!notif, notif || 'none');
  await page.screenshot({ path: SHOTS + '/ui11-03-notif.png' });
  await page.evaluate(() => {
    const rows = [...document.querySelectorAll('.notif-row, .notif-item')];
    const hit = rows.find(r => r.textContent.includes('replied in a thread')); // newest first
    (hit?.querySelector('.notif-main') ?? hit)?.click();
  });
  await page.waitForSelector('.thread-rhs', { timeout: 10000 });
  await sleep(600);
  check('notification click opens the thread', await page.evaluate(() =>
    [...document.querySelectorAll('.thread-rhs .message-row')].some(r => r.textContent.includes('ui reply five'))));

  // ---- pop-out instance overlay ----
  await page.evaluate(() => document.querySelector('.thread-rhs .rhs-head .mud-icon-button')?.click());
  await page.evaluate(() => document.querySelector('.views-btn')?.click());
  await sleep(500);
  await page.evaluate(() => [...document.querySelectorAll('.hdr-menu-item')]
    .find(e => e.textContent.includes('Messenger pop-out'))?.click());
  await page.waitForSelector('.pop-inst-wrap', { timeout: 15000 });
  await sleep(1200);
  const instChip = await page.evaluate(() => {
    const row = [...document.querySelectorAll('.pop-inst-wrap .message-row')].filter(r => r.textContent.includes('ui thread root')).pop();
    return row?.querySelector('.thread-chip')?.textContent.trim() ?? null;
  });
  check('instance list shows the thread chip', !!instChip && /replies/.test(instChip), instChip);
  await page.evaluate(() => {
    const row = [...document.querySelectorAll('.pop-inst-wrap .message-row')].filter(r => r.textContent.includes('ui thread root')).pop();
    row.querySelector('.thread-chip')?.click();
  });
  await page.waitForSelector('.thread-overlay', { timeout: 10000 });
  await sleep(600);
  const overlay = await page.evaluate(() => ({
    root: (document.querySelector('.thread-overlay .message-row')?.textContent || '').includes('ui thread root'),
    replies: [...document.querySelectorAll('.thread-overlay .message-row')].length,
    back: [...document.querySelectorAll('.thread-overlay .thread-bar button')].some(b => b.textContent.includes('Back')),
  }));
  check('instance overlay opens with root + replies + Back', overlay.root && overlay.replies >= 4 && overlay.back,
    JSON.stringify(overlay));
  await page.screenshot({ path: SHOTS + '/ui11-04-instance-overlay.png' });
  await typeIn('.thread-overlay .thread-composer textarea', 'ui reply six');
  await pressEnter('.thread-overlay .thread-composer textarea');
  check('overlay composer sends a reply', await page.evaluate(() =>
    [...document.querySelectorAll('.thread-overlay .message-row')].some(r => r.textContent.includes('ui reply six'))));
  await page.evaluate(() => [...document.querySelectorAll('.thread-overlay .thread-bar button')]
    .find(b => b.textContent.includes('Back'))?.click());
  await sleep(500);
  check('Back closes the overlay', await page.evaluate(() => !document.querySelector('.thread-overlay')));
  const instChip2 = await page.evaluate(() => {
    const row = [...document.querySelectorAll('.pop-inst-wrap .message-row')].filter(r => r.textContent.includes('ui thread root')).pop();
    return row?.querySelector('.thread-chip')?.textContent.trim() ?? null;
  });
  check('instance chip reflects all replies', /6 replies/.test(instChip2 || ''), instChip2);

  await browser.close();
  console.log(`\n${pass}/${pass + fail} PASS`);
  if (fail) process.exit(1);
})().catch(e => { console.error('BATTERY ERROR', e); process.exit(2); });
