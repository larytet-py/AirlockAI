// Static mock runtime: answers the UI's live endpoints with fictional data and turns form submits into a notice.
(function () {
  const G = 2 ** 30;
  const nodes = {
    JaneTestApi: {ip: '10.0.1.11', host: '10.0.1.11', port: 22, up: true, web_up: true, ssh_link_up: true, load1: 0.42, cores: 4,
      disks: [{mount: '/', pct: '61%', used: 29.3 * G, size: 48 * G}, {mount: '/data', pct: '34%', used: 68 * G, size: 200 * G}]},
    JaneTestGateway: {ip: '10.0.3.20', host: 'i-0fedcba9876543210.dev.example.com', port: 22, up: true, web_up: true, ssh_link_up: true,
      load1: 2.91, cores: 2, disks: [{mount: '/', pct: '88%', used: 42.2 * G, size: 48 * G}]},
    LoadTest01: {ip: '10.0.4.8', host: 'i-0123456789abcdef0.dev.example.com', port: 22, up: false, web_up: false, ssh_link_up: false,
      error: 'timeout after 12s'},
    PaymentsSandbox: {ip: '10.0.2.37', host: '10.0.2.37', port: 22, up: true, load1: 0.08, cores: 8,
      disks: [{mount: '/', pct: '22%', used: 21.1 * G, size: 96 * G}]},
  };
  const sessions = {
    '3f2a91c4': {running: true, egress_up: true, cpu: '3.4%', mem: '412 MB', workspace: '18.2 MB'},
    'b71e05d8': {running: false, egress_up: false, cpu: '-', mem: '-', workspace: '2.1 MB'},
    'c9d4e612': {running: true, egress_up: true, cpu: '1.1%', mem: '298 MB', workspace: '640 KB'},
  };
  const clusters = {staging: {up: true, nodes: 4, ms: 212}, production: {up: true, nodes: 9, ms: 187}};
  const dirs = {
    '~': {path: '~', parent: null, dirs: [{name: 'src', path: '~/src'}, {name: 'notes', path: '~/notes'}]},
    '~/src': {path: '~/src', parent: '~', dirs: ['shop-api', 'shop-web', 'infra'].map(n => ({name: n, path: '~/src/' + n, git: true}))},
  };
  const json = (o, status = 200) => Promise.resolve(new Response(JSON.stringify(o), {status, headers: {'content-type': 'application/json'}}));
  const html = s => Promise.resolve(new Response(s, {headers: {'content-type': 'text/html'}}));
  const real = window.fetch.bind(window);
  window.fetch = function (url, opts) {
    const u = new URL(url, location.href), p = u.pathname.replace(/^.*?(\/(api|prod|fs)\/)/, '$1');
    if (p === '/api/nodes/stats') return json(nodes);
    if (p === '/api/sessions/stats') return json(sessions);
    if (p === '/api/prod/stats') return json(clusters);
    if (p === '/fs/dirs') { const d = dirs[u.searchParams.get('path')] || {path: u.searchParams.get('path'), parent: '~/src', dirs: []}; return json(d); }
    const f = (window.MOCK_FRAGMENTS || {})[p];
    if (f !== undefined) return html(f);
    if (u.origin === location.origin) return json({error: 'not available in the mock'}, 404);
    return real(url, opts);
  };
  function notice() {
    let n = document.getElementById('mocknote');
    if (!n) {
      n = document.createElement('div'); n.id = 'mocknote';
      n.style.cssText = 'position:fixed;top:1rem;right:1rem;z-index:100;background:#c2410c;color:#fff;font:14px system-ui;padding:.6rem 1rem;border-radius:6px;box-shadow:0 2px 8px #0004';
      document.body.appendChild(n);
    }
    n.textContent = 'This is a static mock: actions are not performed.';
    n.hidden = false; clearTimeout(n._t); n._t = setTimeout(() => { n.hidden = true }, 2500);
  }
  document.addEventListener('submit', e => {
    e.preventDefault(); notice();
    const b = e.submitter, t = b && b.textContent;   // the real UI turns Start into "Starting..."; undo that here
    if (b) setTimeout(() => { b.disabled = false; b.textContent = t; }, 1500);
  }, true);
  HTMLFormElement.prototype.submit = function () { notice(); };
  window.confirm = () => true;   // the real UI confirms destructive actions; in the mock nothing happens anyway
  document.addEventListener('click', e => {
    const a = e.target.closest('a[href="#"]');
    if (a && !a.onclick && !a.getAttribute('onclick')) { e.preventDefault(); notice(); }
  });
})();
