"""Shared pieces of the controller UI (docs/UI_REFACTOR_SPEC.md section 2): one CSS block, one script block and small
render helpers, used by the EC2, PROD and Settings pages.

Every helper escapes what it is given. The script never puts text from a node, AWS or session state into innerHTML: it
builds elements and sets textContent. Every state change is a plain form POST (UI token cookie, Origin checks).

Patterns, by the spec's ids:
  P1 click a name to edit it        edit_name()                    Enter saves, Esc and blur cancel
  P2 click to copy                  copy_pill()                    Clipboard API, else select + "Press Ctrl+C"
  P3 status chip as action          chip(..., form=...)            a real <button> when there is a next step
  P4 bulk bar on selection          bulk_bar(), row checkboxes     <tr data-kind data-key>, <input class=rowsel>
  P5 row menu                       kebab() + menu()               the ⋯ button and right-click open the same menu
  P6 two clicks for destructive     data-arm="Question?"           first click arms (red), second within 3 s runs
  P8 keyboard                       j k x s Enter Del m ? Esc
"""
from __future__ import annotations

import html

e = html.escape

KIT_CSS = """
:root{--fg:CanvasText;--muted:#888;--line:#8884;--hover:#8881;--panel:Canvas;--accent:#2a6df4;--prod:#c2410c;--ok:#2a9d4a;--bad:#d33;
--warn:#b26b00;--chipbg:#8882;--shadow:0 6px 24px #0003;--mono:ui-monospace,"SF Mono",Menlo,Consolas,monospace}
@media (prefers-color-scheme:dark){:root{--accent:#5a8dff;--ok:#4cc576;--bad:#ff6b5c;--warn:#e6a23c;--prod:#f07a3a;--shadow:0 6px 24px #0009}}
[hidden]{display:none!important}body{background:Canvas;color:CanvasText;overflow-x:hidden}
h2{display:flex;align-items:center;gap:.8rem;flex-wrap:wrap}
.hint{color:var(--muted);font-size:.85rem;font-weight:400}
.tablewrap{overflow-x:auto;border:1px solid var(--line);border-radius:8px;max-width:100%}
.tablewrap table{border-collapse:collapse;width:100%;min-width:760px}
.tablewrap th,.tablewrap td{border-bottom:1px solid var(--line);padding:.45rem .55rem;text-align:left;vertical-align:top}
.tablewrap th{font-size:.78rem;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.04em;vertical-align:middle}
.tablewrap tr:last-child td{border-bottom:0}
.tablewrap tbody tr:hover{background:var(--hover)}
tr.sel{background:color-mix(in srgb,var(--accent) 10%,transparent)!important}
tr.cursor{outline:2px solid var(--accent);outline-offset:-2px}
tr.linked{background:color-mix(in srgb,var(--accent) 16%,transparent)!important}tr.linked td:first-child{box-shadow:inset 4px 0 var(--accent)}
.nm{font-weight:650;cursor:text;border-bottom:1px dotted var(--muted)}.nm:hover{background:var(--hover)}
.sub{color:var(--muted);font:.78rem var(--mono)}.sub a{color:inherit}
.chip{display:inline-flex;align-items:center;gap:.35rem;padding:.1rem .55rem;border-radius:999px;background:var(--chipbg);font-size:.82rem;
white-space:nowrap;border:1px solid transparent;color:CanvasText;font-family:inherit;line-height:1.4}
.chip .dot{width:.55rem;height:.55rem;border-radius:50%;background:currentColor;flex:none}
.chip.c-ok{color:var(--ok)}.chip.c-bad{color:var(--bad)}.chip.c-warn{color:var(--warn)}.chip.c-idle{color:var(--muted)}
.chip .t{color:CanvasText}
button.chip{cursor:pointer}button.chip:hover{border-color:currentColor}
.chip .go{color:var(--muted);font-size:.75rem}
.chip.c-warn.pulse .dot{animation:pulse 1s infinite alternate}@keyframes pulse{to{opacity:.3}}
.meta{display:flex;flex-direction:column;gap:.1rem;color:var(--muted);font-size:.82rem}
.meta.row{flex-direction:row;flex-wrap:wrap;gap:.2rem .9rem}
.meta span span{white-space:nowrap}.meta.load>span,.meta.row>span{white-space:nowrap}.meta b{color:CanvasText;font-weight:500;font-variant-numeric:tabular-nums}.meta .hot,.meta .hot b{color:var(--bad)}
.btn{padding:.22rem .65rem;border-radius:6px;border:1px solid var(--line);background:Canvas;color:CanvasText;cursor:pointer;font:inherit;font-size:.85rem;white-space:nowrap}
.btn:hover{border-color:var(--accent)}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff;font-weight:600}
.btn.danger{color:var(--bad)}
.btn.armed,.menu button.armed{background:var(--bad)!important;border-color:var(--bad)!important;color:#fff!important}
.btn.mini{padding:.05rem .45rem;font-size:.8rem}
.btn:disabled{opacity:.5;cursor:default}
.kebab{width:1.9rem;height:1.7rem;border-radius:6px;border:1px solid transparent;background:none;cursor:pointer;font-size:1.1rem;line-height:1;color:var(--muted)}
.kebab:hover,.kebab[aria-expanded=true]{border-color:var(--line);color:CanvasText}
a.lnk{color:var(--accent);text-decoration:none;font-size:.85rem;white-space:nowrap}a.lnk:hover{text-decoration:underline}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
input.rowsel,input.selall{width:1rem;height:1rem;cursor:pointer}
.cmd{display:inline-flex;align-items:center;gap:.35rem;margin-top:.2rem;font:.78rem var(--mono);background:var(--chipbg);color:CanvasText;
border:1px solid transparent;border-radius:4px;padding:.05rem .4rem;cursor:copy;max-width:100%}
.cmd .ct{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.cmd:hover{border-color:var(--accent)}
.cmd .ic{color:var(--muted);font-family:system-ui}.cmd.done{border-color:var(--ok);color:var(--ok)}
.acts{display:flex;gap:.6rem;align-items:center;justify-content:flex-end}.opens{display:flex;gap:.7rem;margin-top:.2rem}
.menu{position:fixed;z-index:50;min-width:13rem;background:Canvas;border:1px solid var(--line);border-radius:8px;box-shadow:var(--shadow);padding:.3rem;font-size:.88rem}
.menu .hd{padding:.3rem .6rem .2rem;color:var(--muted);font-size:.75rem;text-transform:uppercase;letter-spacing:.05em}
.menu button,.menu a{display:flex;width:100%;box-sizing:border-box;justify-content:space-between;gap:1rem;padding:.38rem .6rem;border:0;background:none;
border-radius:5px;cursor:pointer;text-align:left;font:inherit;color:CanvasText;text-decoration:none}
.menu button:hover:not(:disabled),.menu a:hover,.menu button:focus-visible,.menu a:focus-visible{background:var(--hover);outline:none}
.menu button:disabled{opacity:.45;cursor:default}.menu .danger{color:var(--bad)}.menu .k{color:var(--muted);font:.75rem var(--mono)}
.menu hr{border:0;border-top:1px solid var(--line);margin:.3rem 0}
.bbar{position:fixed;left:50%;transform:translateX(-50%);bottom:1rem;z-index:40;display:flex;flex-wrap:wrap;align-items:center;gap:.4rem;
background:CanvasText;color:Canvas;border-radius:10px;padding:.45rem .55rem .45rem .9rem;box-shadow:var(--shadow);max-width:calc(100vw - 32px)}
.bbar .count{font-weight:650;margin-right:.3rem}
.bbar .btn{background:transparent;color:Canvas;border-color:color-mix(in srgb,Canvas 35%,transparent)}
.bbar .btn:hover{border-color:Canvas}.bbar .btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}
.bbar .btn.danger{color:var(--bad);border-color:color-mix(in srgb,var(--bad) 60%,transparent)}
.bbar .x{background:none;border:0;color:Canvas;opacity:.7;cursor:pointer;font-size:1.1rem;padding:0 .3rem}
.inline{display:flex!important;flex-wrap:wrap;gap:.3rem;align-items:center;margin-top:.3rem}
.inline[hidden]{display:none!important}
.card{display:flex;flex-wrap:wrap;gap:.5rem 1rem;align-items:center;justify-content:space-between;border:1px solid var(--line);
border-left:4px solid var(--prod);border-radius:8px;padding:.55rem .8rem;margin:.5rem 0}
.card .body{min-width:0;flex:1 1 20rem}.card .args{font:.8rem var(--mono);color:var(--muted);overflow-wrap:anywhere;white-space:pre-wrap;margin:.2rem 0}
.empty{color:var(--muted);padding:.6rem;border:1px dashed var(--line);border-radius:8px}
dialog.keys{border:1px solid var(--line);border-radius:10px;box-shadow:var(--shadow);max-width:26rem;background:Canvas;color:CanvasText}
dialog.keys dl{display:grid;grid-template-columns:auto 1fr;gap:.35rem .9rem;margin:.6rem 0 0}dialog.keys dt{text-align:right}
kbd{font:600 .75rem var(--mono);border:1px solid var(--line);border-bottom-width:2px;border-radius:4px;padding:0 .3rem}
@media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
"""

# One hidden form for every one-row action: the clicked button carries formaction and its single name=value (P7.2).
# The key list (P8) as a dialog.
KIT_HTML = """<form id=act method=post hidden></form>
<div class=menu id=multimenu role=menu hidden><div class=hd></div><div style="padding:.3rem .6rem;color:var(--muted)">Use the bar at the bottom for the ticked rows.</div></div>
<dialog class=keys id=keys aria-label="Keyboard shortcuts"><b>Mouse and keyboard</b><dl>
<dt>click name</dt><dd>edit it (Enter saves, Esc cancels)</dd><dt>click ssh &hellip;</dt><dd>copy the command</dd>
<dt><kbd>j</kbd> <kbd>k</kbd></dt><dd>move between rows</dd><dt><kbd>x</kbd></dt><dd>tick the row</dd>
<dt><kbd>s</kbd></dt><dd>start a session on the node (or on the ticked nodes)</dd><dt><kbd>Enter</kbd></dt><dd>open claude for the session</dd>
<dt><kbd>Del</kbd></dt><dd>remove the session (press twice if it is running)</dd><dt><kbd>m</kbd></dt><dd>open the row menu</dd>
<dt><kbd>Esc</kbd></dt><dd>close the menu, clear the selection</dd></dl>
<p style="margin:.8rem 0 0;text-align:right"><button class=btn type=button onclick="this.closest('dialog').close()">Close</button></p></dialog>"""

KIT_JS = r"""
// ---- shared UI behaviour (docs/UI_REFACTOR_SPEC.md section 2). Data never goes in as markup: elements + textContent only.
const $=(s,r=document)=>r.querySelector(s),$$=(s,r=document)=>[...r.querySelectorAll(s)];
function el(tag,attrs,...kids){const x=document.createElement(tag);for(const[k,v]of Object.entries(attrs||{})){if(v==null||v===false)continue;
  if(k==='class')x.className=v;else x.setAttribute(k,v===true?'':v)}for(const c of kids)if(c!=null)x.append(c);return x}
function chipEl(cls,label,go){const c=el(go?'button':'span',{class:'chip '+cls},el('span',{class:'dot'}),el('span',{class:'t'},label));
  if(go){c.type='submit';c.append(el('span',{class:'go'},go))}return c}

// P1: click a name to edit it. Enter saves, Esc and blur cancel.
function rn(el){const w=el.closest('.nmwrap'),f=w.querySelector('form'),i=f.querySelector('input');el.hidden=true;f.hidden=false;i.focus();i.select()}
function rnCancel(i){const w=i.closest('.nmwrap');i.value=i.dataset.orig;w.querySelector('form').hidden=true;w.querySelector('.nm').hidden=false}
function rnKey(ev,i){if(ev.key==='Escape'){ev.preventDefault();ev.stopPropagation();rnCancel(i)}else if(ev.key==='Enter'){ev.preventDefault();
  if(i.value.trim()===i.dataset.orig){rnCancel(i);return}i.onblur=null;if(i.form.reportValidity())i.form.requestSubmit();else i.onblur=()=>rnCancel(i)}}
document.addEventListener('keydown',ev=>{if(ev.key==='Enter'&&ev.target.classList&&ev.target.classList.contains('nm')){ev.preventDefault();rn(ev.target)}});

// P2: click to copy. Clipboard API first; if refused, select the text and ask for Ctrl+C.
document.addEventListener('click',ev=>{const b=ev.target.closest('.cmd[data-copy]');if(!b)return;ev.preventDefault();ev.stopPropagation();
  const t=b.querySelector('.ct'),ic=b.querySelector('.ic'),text=t.textContent;
  const ok=()=>{b.classList.add('done');ic.textContent='copied';setTimeout(()=>{b.classList.remove('done');ic.textContent='⧉'},1000)};
  const fb=()=>{const r=document.createRange();r.selectNodeContents(t);const s=getSelection();s.removeAllRanges();s.addRange(r);
    ic.textContent='Press Ctrl+C';setTimeout(()=>{ic.textContent='⧉'},2500)};
  try{navigator.clipboard.writeText(text).then(ok,fb)}catch(e){fb()}},true);

// P6: two clicks for destructive buttons. The first click arms (red, label = the question); a second within 3 s runs it.
function disarm(b){if(!b.classList.contains('armed'))return;b.classList.remove('armed');b.textContent=b.dataset.orig}
function arm(b){b.dataset.orig=b.textContent;b.classList.add('armed');b.textContent=b.dataset.arm;clearTimeout(b._t);b._t=setTimeout(()=>disarm(b),3000)}
document.addEventListener('click',ev=>{const b=ev.target.closest('button[data-arm]');if(!b||b.disabled||!b.dataset.arm)return;
  const cond=b.dataset.armIf;if(cond){const[k,v]=cond.split('=');const f=b.form,x=f&&f.elements[k];if(!x||x.value!==v)return}
  if(b.classList.contains('armed'))return;   // second click: let the form submit
  ev.preventDefault();ev.stopImmediatePropagation();arm(b)},true);

// ARM_END
// P4: row selection and the bulk bar. One kind of row at a time; the bar acts on the ticked rows of that kind.
const rowsOf=kind=>$$(`tr[data-kind="${kind}"]`);
const isTicked=r=>{const c=r.querySelector('input.rowsel');return !!(c&&c.checked)};
const ticked=kind=>rowsOf(kind).filter(isTicked);
const fits=(r,need)=>!need||need.split('|').some(n=>r.dataset[n]==='1');
function clearTicks(except){for(const c of $$('input.rowsel'))if(c.closest('tr').dataset.kind!==except)c.checked=false}
function syncBars(){
  for(const r of $$('tr[data-kind]'))r.classList.toggle('sel',isTicked(r));
  for(const a of $$('input.selall')){const rs=rowsOf(a.dataset.for);a.checked=rs.length>0&&rs.every(isTicked)}
  for(const bar of $$('.bbar[data-for]')){const t=ticked(bar.dataset.for);bar.hidden=!t.length;if(!t.length){$$('button.armed',bar).forEach(disarm);continue}
    $('.count',bar).textContent=t.length+' '+(t.length>1?bar.dataset.plural:bar.dataset.singular);
    for(const b of $$('button[data-need]',bar)){const n=t.filter(r=>fits(r,b.dataset.need)).length;b.disabled=!n;
      if(b.dataset.label1&&!b.classList.contains('armed'))b.textContent=n>1?b.dataset.labeln.replace('{n}',n):b.dataset.label1}
    for(const b of $$('button[data-arm-tpl]',bar)){const n=t.filter(r=>fits(r,b.dataset.armNeed||b.dataset.need)).length;
      if(n&&!b.disabled)b.dataset.arm=b.dataset.armTpl.replace('{n}',n);else{disarm(b);delete b.dataset.arm}}}
  linkRows()}
// Ticked nodes (or clusters) and the row cursor light up the session rows that use them.
const LINKS={nodes:'sess',env:'psess'};
function linkRows(){for(const[from,to]of Object.entries(LINKS)){const keys=new Set(ticked(from).map(r=>r.dataset.key));
  if(cursorRow&&cursorRow.dataset.kind===from)keys.add(cursorRow.dataset.key);
  for(const r of rowsOf(to))r.classList.toggle('linked',(r.dataset.targets||'').split(',').some(k=>keys.has(k)))}}
document.addEventListener('change',ev=>{const c=ev.target;
  if(c.classList.contains('rowsel')){if(c.checked)clearTicks(c.closest('tr').dataset.kind);syncBars()}
  else if(c.classList.contains('selall')){clearTicks(c.dataset.for);for(const r of rowsOf(c.dataset.for)){const x=r.querySelector('input.rowsel');if(x)x.checked=c.checked}syncBars()}});
document.addEventListener('click',ev=>{const x=ev.target.closest('.bbar .x');if(x){clearTicks();syncBars()}});
// A bar button with data-only acts on the ticked rows it applies to: the others are unticked just before the form is sent.
document.addEventListener('submit',ev=>{const b=ev.submitter;if(!b)return;
  if(b.dataset.only!==undefined){const bar=b.closest('.bbar');for(const r of ticked(bar.dataset.for))if(!fits(r,b.dataset.need)){r.querySelector('input.rowsel').checked=false}}
  if(b.dataset.busy)setTimeout(()=>{b.textContent=b.dataset.busy;b.disabled=true},0)});

// P5: row menu. The ⋯ button and right-click on the row open the same menu; several ticked rows point to the bar.
let openM=null,opener=null;
function closeMenu(refocus){if(!openM)return;$$('button.armed',openM).forEach(disarm);openM.hidden=true;openM=null;
  if(opener){opener.setAttribute('aria-expanded','false');if(refocus)opener.focus()}opener=null}
function place(m,x,y){m.hidden=false;const r=m.getBoundingClientRect();
  m.style.left=Math.max(8,Math.min(x,innerWidth-r.width-8))+'px';m.style.top=Math.max(8,y+r.height>innerHeight-8?y-r.height:y)+'px'}
function rowMenu(row,x,y,anchor){closeMenu();const t=ticked(row.dataset.kind);let m;
  if(t.length>1&&t.includes(row)){m=$('#multimenu');$('.hd',m).textContent=t.length+' selected, use the bar'}else m=row.querySelector('.menu');
  if(!m)return;refreshMenu(row,m);place(m,x,y);openM=m;opener=anchor||null;if(anchor)anchor.setAttribute('aria-expanded','true');
  const first=m.querySelector('button:not(:disabled):not([hidden]),a:not([hidden])');if(first)first.focus()}
function refreshMenu(row,m){for(const b of $$('[data-need]',m))b.disabled=!fits(row,b.dataset.need);
  for(const b of $$('[data-show]',m))b.hidden=!fits(row,b.dataset.show)}
document.addEventListener('click',ev=>{const k=ev.target.closest('.kebab');
  if(k){ev.preventDefault();ev.stopPropagation();if(openM&&opener===k){closeMenu(true);return}const r=k.getBoundingClientRect();rowMenu(k.closest('tr'),r.right-220,r.bottom+4,k);return}
  const it=ev.target.closest('.menu [data-act]');
  if(it){const row=it.closest('tr');closeMenu(false);
    if(it.dataset.act==='rename'){const n=row&&row.querySelector('.nm');if(n)rn(n)}
    else if(it.dataset.act==='reveal'){const f=document.getElementById(it.dataset.target);if(f){f.hidden=false;const i=f.querySelector('input,select,textarea');if(i)i.focus()}}
    return}
  if(openM&&!ev.target.closest('.menu'))closeMenu(false)});
document.addEventListener('click',ev=>{const h=ev.target.closest('[data-hide]');if(h){const f=document.getElementById(h.dataset.hide);if(f)f.hidden=true}});
document.addEventListener('contextmenu',ev=>{const row=ev.target.closest('tr[data-kind]');if(!row||ev.target.closest('a,input,textarea,.cmd'))return;
  ev.preventDefault();rowMenu(row,ev.clientX,ev.clientY,row.querySelector('.kebab'))});
addEventListener('scroll',()=>closeMenu(false),true);addEventListener('resize',()=>closeMenu(false));

// P8: keyboard. Ignored while typing in a field.
let cursorRow=null;
function setCursor(r){if(cursorRow)cursorRow.classList.remove('cursor');cursorRow=r;if(r){r.classList.add('cursor');r.scrollIntoView({block:'nearest'})}linkRows()}
document.addEventListener('click',ev=>{const r=ev.target.closest('tr[data-kind]');if(r&&!ev.target.closest('button,a,input,form'))setCursor(r)});
document.addEventListener('keydown',ev=>{
  if(ev.ctrlKey||ev.metaKey||ev.altKey)return;
  if(ev.target.closest&&ev.target.closest('input:not([type=checkbox]),textarea,select,[contenteditable]'))return;
  if(openM){const items=$$('button:not(:disabled):not([hidden]),a:not([hidden])',openM),i=items.indexOf(document.activeElement);
    if(ev.key==='ArrowDown'){ev.preventDefault();(items[(i+1)%items.length]||items[0]).focus()}
    else if(ev.key==='ArrowUp'){ev.preventDefault();(items[(i-1+items.length)%items.length]||items[0]).focus()}
    else if(ev.key==='Escape'){ev.preventDefault();closeMenu(true)}
    else if((ev.key==='Delete'||ev.key==='Backspace')&&document.activeElement.matches('[data-rm]')){ev.preventDefault();document.activeElement.click()}
    return}
  if($('#keys')&&$('#keys').open)return;
  if(ev.key==='Escape'){if($$('input.rowsel:checked').length){clearTicks();syncBars()}else setCursor(null);return}
  if(ev.key==='?'){ev.preventDefault();$('#keys').showModal();return}
  const rows=$$('tr[data-kind]').filter(r=>r.offsetParent!==null);if(!rows.length)return;
  const i=rows.indexOf(cursorRow);
  if(ev.key==='j'){setCursor(rows[Math.min(rows.length-1,i+1)]);return}
  if(ev.key==='k'){setCursor(rows[Math.max(0,i-1)]);return}
  if(ev.key==='s'){const bar=$('.bbar[data-for=nodes]:not([hidden]),.bbar[data-for=env]:not([hidden])'),b=bar&&$('button[data-start]',bar);
    if(b){if(!b.disabled)b.click();return}
    if(cursorRow){const m=cursorRow.querySelector('.menu [data-start]');if(m){refreshMenu(cursorRow,m.closest('.menu'));if(!m.disabled)m.click()}}return}
  if(!cursorRow)return;
  if(ev.key==='x'){const c=cursorRow.querySelector('input.rowsel');if(c){c.checked=!c.checked;c.dispatchEvent(new Event('change',{bubbles:true}))}return}
  if(ev.key==='m'){const k=cursorRow.querySelector('.kebab');if(k){const r=k.getBoundingClientRect();rowMenu(cursorRow,r.right-220,r.bottom+4,k)}return}
  if(ev.key==='Enter'&&ev.target===document.body){const a=cursorRow.querySelector('a[data-claude]');if(a){ev.preventDefault();a.click()}return}
  if(ev.key==='Delete'||ev.key==='Backspace'){const b=cursorRow.querySelector('.menu [data-rm]'),k=cursorRow.querySelector('.kebab');
    if(b&&k){ev.preventDefault();const r=k.getBoundingClientRect();rowMenu(cursorRow,r.right-220,r.bottom+4,k);b.focus();b.click()}}});

// Reload the page (to show a session that left "starting", for example) only while nobody is in the middle of something.
function idle(){const a=document.activeElement;
  return !openM&&!$$('input.rowsel:checked').length&&!$('button.armed')&&!($('#keys')&&$('#keys').open)&&
    !(a&&a.closest&&a.closest('input:not([type=checkbox]),textarea,select'))&&!$$('form.inline:not([hidden]),.nmwrap form:not([hidden])').length}
function freshReload(){location.replace(location.pathname+(location.pathname==='/'?'?tab=ec2':''))}

// Session rows (both tabs): live agent chip, ✕ needs two clicks only while running, "Remove N not running", start progress.
const fmtSecs=s=>s<90?s+'s':Math.floor(s/60)+'m '+(s%60)+'s';
function sessionTick(d){let dead=0,reload=false;
  for(const row of $$('tr[data-kind=sess],tr[data-kind=psess]')){const s=d[row.dataset.key];const life=row.dataset.life;
    if(s&&s.status&&s.status!==life)reload=true;
    if(life==='running'){const live=!!(s&&s.running),cell=row.querySelector('[data-f=agent]');
      row.dataset.live=live?'1':'0';row.dataset.dead=live?'0':'1';
      if(cell){cell.textContent='';
        if(live)cell.append(chipEl('c-ok','running'));
        else{const b=chipEl('c-bad','NOT RUNNING','✕ remove');b.setAttribute('form',row.dataset.rmform);b.setAttribute('formaction',row.dataset.rmaction);
          b.name='ssel';b.value=row.dataset.key;b.title='The agent container is gone. Click to remove the session.';cell.append(b)}}
      const rm=row.querySelector('button[data-rm]');if(rm){if(live)rm.dataset.arm='Stop & remove?';else{disarm(rm);delete rm.dataset.arm}}
      for(const x of $$('[data-liveonly]',row))x.hidden=!live;
      if(s)for(const f of ['cpu','mem','workspace']){const c=row.querySelector(`[data-f=${f}]`);if(c)c.textContent=live?s[f]:'-'}}
    if(row.dataset.dead==='1')dead++}
  for(const p of $$('button[data-prune]')){p.hidden=!dead;p.textContent=`Remove ${dead} not running`}
  for(const n of $$('tr[data-kind=nodes]')){const c=n.querySelector('[data-f=nsess]');if(!c)continue;let l=0,k=0;
    for(const r of $$('tr[data-kind=sess]'))if((r.dataset.nodes||'').split(',').includes(n.dataset.key)){if(r.dataset.dead==='1')k++;else l++}
    c.textContent='';if(!l&&!k){c.append(el('span',{class:'hint'},'–'))}
    else{const m=el('span',{class:'meta row'});if(l)m.append(el('span',{},el('b',{},String(l)),' running'));if(k)m.append(el('span',{class:'hot'},el('b',{},String(k)),' not running'));c.append(m)}}
  if(reload&&idle())freshReload();
  const st=$('#stamp');if(st)st.textContent='updated '+new Date().toLocaleTimeString()}
setInterval(()=>{for(const c of $$('[data-starting]')){const s=Math.max(0,Math.round(Date.now()/1000-Number(c.dataset.starting)));const t=c.querySelector('.t');if(t)t.textContent='starting… '+fmtSecs(s)}},1000);
async function sessionPoll(){try{const r=await fetch('/api/sessions/stats');if(r.ok)sessionTick(await r.json())}catch(e){}}
if($('tr[data-kind=sess],tr[data-kind=psess]')){sessionPoll();setInterval(sessionPoll,5000)}
syncBars();
"""


def kit_head() -> str:
    """The shared CSS, for inclusion inside a page's <style>."""
    return KIT_CSS


def kit_tail() -> str:
    """The shared hidden elements and the script, placed once at the end of <main>."""
    return KIT_HTML + "<script>" + KIT_JS + "</script>"


def copy_pill(text: str) -> str:
    """P2: a monospace pill that copies `text`. It only copies: it never runs anything and never links to ssh://."""
    return (f'<button type=button class=cmd data-copy title="Click to copy" aria-label="Copy: {e(text)}">'
            f'<span class=ct>{e(text)}</span><span class=ic aria-hidden=true>&#x29c9;</span></button>')


def edit_name(shown: str, action: str, *, field: str = "new", value: str | None = None, pattern: str = "",
              placeholder: str = "", title: str = "Click to rename", required: bool = True, size: int = 28) -> str:
    """P1: the name as text with a dotted underline; click (or Enter) turns it into a field posting to `action`."""
    value = shown if value is None else value
    pat = f' pattern="{e(pattern)}"' if pattern else ""
    return (f'<div class=nmwrap><span class=nm role=button tabindex=0 title="{e(title)}" onclick="rn(this)">{e(shown)}</span>'
            f'<form method=post action="{e(action)}" hidden><input name={field} value="{e(value)}" size={size} autocomplete=off spellcheck=false'
            f'{" required" if required else ""} data-orig="{e(value)}" placeholder="{e(placeholder)}" aria-label="{e(title)}"{pat} '
            f'onkeydown="rnKey(event,this)" onblur="rnCancel(this)"></form></div>')


def chip(cls: str, label: str, go: str = "", *, title: str = "", attrs: str = "") -> str:
    """P3: a status chip. With `go` (the next step, e.g. "✕ remove") it is a real <button>; `attrs` carries form/formaction."""
    t = f' title="{e(title)}"' if title else ""
    inner = f'<span class=dot></span><span class=t>{e(label)}</span>'
    if go:
        return f'<button class="chip {cls}"{t} {attrs}>{inner}<span class=go>{e(go)}</span></button>'
    return f'<span class="chip {cls}"{t} {attrs}>{inner}</span>'


def post_btn(label: str, action: str, name: str, value: str, *, cls: str = "btn", form: str = "act", arm: str = "",
             title: str = "", aria: str = "", extra: str = "") -> str:
    """A one-row action: posts `name=value` to `action` through the shared hidden form (or `form`). `arm` makes it P6."""
    a = f' data-arm="{e(arm)}"' if arm else ""
    t = f' title="{e(title)}"' if title else ""
    al = f' aria-label="{e(aria)}"' if aria else ""
    return (f'<button class="{cls}" form={form} formaction="{e(action)}" name="{e(name)}" value="{e(value)}"{a}{t}{al} {extra}>'
            f'{e(label)}</button>')


def kebab(what: str) -> str:
    return (f'<button type=button class=kebab aria-label="More actions for {e(what)}" aria-haspopup=menu aria-expanded=false>'
            '&#x22ef;</button>')


def menu(title: str, items: list[str]) -> str:
    """P5: the row's menu (hidden until the ⋯ button or a right-click opens it). Items: mi_*() strings, or "-" for a rule."""
    body = "".join("<hr>" if it == "-" else it for it in items)
    return f'<div class=menu role=menu hidden aria-label="Actions for {e(title)}"><div class=hd>{e(title)}</div>{body}</div>'


def mi_post(label: str, action: str, name: str, value: str, *, arm: str = "", danger: bool = False, key: str = "",
            need: str = "", show: str = "", role: str = "menuitem", checked: bool | None = None, extra: str = "") -> str:
    attrs = [f'role={role}', 'form=act', f'formaction="{e(action)}"', f'name="{e(name)}"', f'value="{e(value)}"']
    if arm:
        attrs.append(f'data-arm="{e(arm)}"')
    if danger:
        attrs.append("class=danger")
    if need:
        attrs.append(f'data-need="{need}"')
    if show:
        attrs.append(f'data-show="{show}"')
    if checked is not None:
        attrs.append(f'aria-checked={"true" if checked else "false"}')
    if extra:
        attrs.append(extra)
    return f'<button {" ".join(attrs)}><span>{e(label)}</span><span class=k>{e(key)}</span></button>'


def mi_act(label: str, act: str, *, target: str = "", key: str = "") -> str:
    t = f' data-target="{e(target)}"' if target else ""
    return f'<button type=button role=menuitem data-act={act}{t}><span>{e(label)}</span><span class=k>{e(key)}</span></button>'


def mi_link(label: str, href: str, *, newtab: bool = False, key: str = "", extra: str = "") -> str:
    tgt = " target=_blank rel=noopener" if newtab else ""
    return f'<a role=menuitem href="{e(href)}"{tgt} {extra}><span>{e(label)}</span><span class=k>{e(key)}</span></a>'


def bulk_bar(kind: str, singular: str, plural: str, buttons: list[str]) -> str:
    """P4: shown only while rows of `kind` are ticked. Buttons use the table's own form (its checkboxes carry the values)."""
    return (f'<div class=bbar data-for={kind} data-singular="{e(singular)}" data-plural="{e(plural)}" hidden role=toolbar '
            f'aria-label="Ticked {e(plural)}"><span class=count></span>{"".join(buttons)}'
            '<button type=button class=x aria-label="Clear selection">&times;</button></div>')


def bar_btn(label: str, form: str, action: str, *, need: str = "", only: bool = False, labeln: str = "", arm: str = "",
            arm_need: str = "", primary: bool = False, danger: bool = False, busy: str = "", start: bool = False) -> str:
    """A bulk-bar button. `need`: row flags it applies to (disabled when none ticked has them); `only`: send just those rows;
    `labeln`: label when more than one applies ("Start {n} sessions"); `arm`: the P6 question ({n} = applicable rows);
    `arm_need`: arm only when a ticked row has that flag (else one click)."""
    cls = "btn" + (" primary" if primary else "") + (" danger" if danger else "")
    a = [f'class="{cls}"', f"form={form}", f'formaction="{e(action)}"']
    if need:
        a.append(f'data-need="{need}"')
    if only:
        a.append("data-only")
    if labeln:
        a += [f'data-label1="{e(label)}"', f'data-labeln="{e(labeln)}"']
    if arm:
        a.append(f'data-arm-tpl="{e(arm)}"' + (f' data-arm-need="{arm_need}"' if arm_need else ""))
    if busy:
        a.append(f'data-busy="{e(busy)}"')
    if start:
        a.append("data-start")
    return f'<button {" ".join(a)}>{e(label)}</button>'


# P6 alone, for pages that do not load the whole kit (Settings > Access)
ARM_JS = KIT_JS[KIT_JS.index("// P6:"):KIT_JS.index("// ARM_END")]
