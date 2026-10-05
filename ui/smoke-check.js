// app.js 启动链路运行时冒烟（3.0.0 教训产物）：node ui/smoke-check.js
// 用 DOM/Tauri 桩真实执行 app.js 的 DOMContentLoaded 链路，
// 捕获运行时异常并断言「启动弹窗 / 拖放注册 / 事件监听 / frontend_ready」就绪。
// 此前误删大段前端代码仅靠 node --check 语法检查没能发现 —— 语义级冒烟由此而来。
const fs = require('fs');
const vm = require('vm');

const src = fs.readFileSync('ui/app.js', 'utf8');
const calls = { startup: 0, bindEvents: 0, hideDialog: 0, setStatusMsg: '' };

function makeEl(id) {
    const el = {
        id, textContent: '', value: '', style: {},
        children: [],
        dataset: {},
        addEventListener() {}, removeEventListener() {},
    };
    // 3.0.1（#33 修复）：classList 追踪真实类集合 —— 启动弹窗的「已显示」
    // 判定依赖 contains('hidden') 为假（此前桩恒返回 false，断言是空操作）
    el.__classes = new Set();
    el.classList = {
        add: (...cs) => cs.forEach(c => el.__classes.add(c)),
        remove: (...cs) => cs.forEach(c => el.__classes.delete(c)),
        contains: (c) => el.__classes.has(c),
        toggle: (c) => { el.__classes.has(c) ? el.__classes.delete(c) : el.__classes.add(c); },
    };
    el.appendChild = (c) => {
        el.children.push(c); c.parent = el;
    };
    el.removeChild = (c) => { el.children = el.children.filter(x => x !== c); };
    el.remove = () => { if (el.parent) el.parent.removeChild(el); };
    const matches = (c, sel) => {
        // 支持子集：tag / #id / .class / :not(:disabled)，空格分层
        const parts = sel.trim().split(/\s+/);
        let cur = [c];
        for (const part of parts) {
            const next = [];
            for (const n of cur) {
                for (const ch of n.children || []) {
                    let ok = true;
                    const m = part.match(/^([a-z]+)(.*)$/i);
                    if (m) {
                        if (ch.tagName !== m[1].toUpperCase() && ch.tag !== m[1].toLowerCase()) ok = false;
                        let rest = m[2] || '';
                        const idm = rest.match(/#([\w-]+)/);
                        if (idm && ch.id !== idm[1]) ok = false;
                        const clsm = rest.match(/\.([\w-]+)/g) || [];
                        for (const cl of clsm) {
                            const cls = cl.slice(1);
                            if (!String(ch.className || '').split(/\s+/).includes(cls)) ok = false;
                        }
                        if (rest.includes(':not(:disabled)') && ch.disabled) ok = false;
                    } else if (part.startsWith('#')) {
                        if (ch.id !== part.slice(1)) ok = false;
                    } else if (part.startsWith('.')) {
                        // 3.0.1（#32 修复）：纯 class 选择器（buildFileRow 的
                        // querySelector('.fi-icon') 依赖）—— 多类链 '.a.b' 逐段匹配
                        const want = part.split('.').filter(Boolean);
                        const have = String(ch.className || '').split(/\s+/);
                        if (!want.every(w => have.includes(w))) ok = false;
                    } else { ok = false; }
                    if (ok) next.push(ch);
                }
            }
            cur = next;
            if (cur.length === 0) return [];
        }
        return cur;
    };
    el.querySelector = (sel) => matches(el, sel)[0] || null;
    el.querySelectorAll = (sel) => matches(el, sel);
    el.setAttribute = () => {};
    el.getAttribute = () => null;
    el.focus = () => { el.focused = true; };
    el.select = () => {};
    el.click = () => { if (el.onclick) el.onclick({ preventDefault() {} }); };
    el.disabled = false;
    el.checked = false;
    el.href = '';
    el.isConnected = true;
    el.parentNode = null;
    el.onclick = null;
    el.handlers = {};
    Object.defineProperty(el, 'innerHTML', {
        get() { return el.__html || ''; },
        set(v) {
            el.__html = v;
            el.children = [];
            // 轻量解析 <input id="..." type="...">、<span class="..."> 与
            // <button> —— 供查询器与回车测试。
            // 3.0.1（#32 修复）：补 span 解析 —— buildFileRow 的行内结构是
            // <span class="fi-icon/fi-name/fi-size">，不解析则 querySelector
            // 返回 null，渲染链冒烟覆盖不到真实结构
            const re = /<input[^>]*id="([\w-]+)"[^>]*>/g;
            let m;
            globalThis.__parsed = (globalThis.__parsed || 0);
            while ((m = re.exec(v)) !== null) {
                globalThis.__parsed++;
                const inp = makeEl(m[1]);
                inp.tagName = 'INPUT';
                inp.tag = 'input';
                const tm = m[0].match(/type="([\w-]+)"/);
                if (tm) inp.type = tm[1];
                el.children.push(inp);
                inp.parent = el;
                elements[m[1]] = inp; // 注册进缓存（$ 可寻址）
            }
            const spanRe = /<span[^>]*class="([\w-]+)"[^>]*>/g;
            while ((m = spanRe.exec(v)) !== null) {
                const sp = makeEl('span-' + m[1]);
                sp.tagName = 'SPAN';
                sp.tag = 'span';
                sp.className = m[1];
                el.children.push(sp);
                sp.parent = el;
            }
        },
    });
    el.addEventListener = (ev, fn) => { (el.handlers[ev] = el.handlers[ev] || []).push(fn); };
    el.fireKey = (key) => {
        const ev = {
            key, target: el, shiftKey: false, ctrlKey: false, altKey: false, metaKey: false,
            preventDefault() { ev.defaultPrevented = true; },
            defaultPrevented: false,
        };
        // 沿 parent 链冒泡（对齐真实 DOM）；preventDefault 终止传播
        let node = el;
        while (node) {
            for (const fn of node.handlers.keydown || []) {
                fn(ev);
                if (ev.defaultPrevented) return;
            }
            node = node.parent;
        }
    };
    return el;
}

const elements = {};
// 静态 HTML 层级（index.html 的关键子树）—— 查询器按真实 DOM 层级工作
const STATIC_TREE = {
    dialog: ['dialog-title', 'dialog-body', 'dialog-buttons'],
    'startup-dialog': ['startup-list', 'sd-create', 'sd-open', 'sd-open-other'],
    app: ['titlebar', 'toolbar', 'nav', 'file-list', 'status-bar', 'repo-link',
          'btn-close', 'btn-add-part', 'btn-del-part', 'btn-duress', 'btn-yk',
          'btn-import-file', 'btn-import-folder', 'btn-newfolder', 'btn-extract-all',
          'btn-defrag', 'btn-destroy', 'btn-change-pwd', 'btn-audit', 'btn-verify'],
    'ctx-menu': [],
};
const $ = (sel) => {
    const key = sel.startsWith('#') ? sel.slice(1) : sel;
    if (!elements[key]) {
        elements[key] = makeEl(key);
        // 挂到静态父节点（层级树）
        for (const [parent, kids] of Object.entries(STATIC_TREE)) {
            if (kids.includes(key)) {
                const p = $(parent);
                p.children.push(elements[key]);
                elements[key].parent = p;
            }
        }
    }
    return elements[key];
};

const tauriInvoke = async (cmd, args) => {
    if (cmd === 'get_settings') return { enabled: false, settings: null };
    // 3.0.1（#33 修复）：返回一条假条目驱动 renderStartupList 渲染链，
    // 「启动弹窗已显示」断言从永真式改为可观测信号
    if (cmd === 'scan_vault_files') return [
        { path: 'C:\\fake\\demo.lyt', name: 'demo.lyt', mtime: 1700000000, size: 4096 },
    ];
    if (cmd === 'get_lock_info') return null;
    if (cmd === 'frontend_ready') return null;
    if (cmd === 'get_launch_vault_arg') return null;
    if (cmd === 'check_vault_file') return false;
    if (cmd === 'get_file_icon') return '';
    // 3.0.1（#32 修复）：后端 list_folder 返回结构化**数组** —— 旧 mock 是
    // 对象，(data||[]).map 抛错走 catch 分支，buildFileRow 0 覆盖且冒烟 PASS。
    // 返回两行真实形状数据驱动完整渲染链（buildFileRow → mountRows）。
    if (cmd === 'list_folder') {
        return [
            { name: '文件夹甲', vpath: '/文件夹甲', type: 'folder' },
            { name: 'sample.txt', vpath: '/sample.txt', type: 'file', size: 2048 },
        ];
    }
    if (cmd === 'get_duress_status') return { marked: false, partitions: ['Main', 'Decoy'], active: 'Main' };
    if (cmd === 'yubikey_status') return { enabled: false, present: true };
    if (cmd === 'add_partition') return {};
    if (cmd === 'set_duress_mark') return {};
    if (cmd === 'clear_duress_mark') return {};
    if (cmd === 'enable_yubikey_2fa') return {};
    if (cmd === 'duress_rehearsal') return { wiped: 1 };
    if (cmd === 'duress_scrub_partitions') return { scrubbed: 4096 };
    return { ok: true };
};

const sandbox = {
    console,  // 调试期启用真实 console
    setTimeout: (fn) => 0, clearTimeout() {},
    setInterval: () => 0, clearInterval() {},
    TextEncoder, TextDecoder, btoa: (s) => Buffer.from(s, 'binary').toString('base64'),
    navigator: { userAgent: 'Windows' },
    window: null,
    document: {
        addEventListener(ev, fn) { if (ev === 'DOMContentLoaded') (sandbox.__domReadyFns = sandbox.__domReadyFns || []).push(fn); },
        removeEventListener() {},
        getElementById: (id) => $(id),
        createElement: (t) => { const e = makeEl(t); e.tag = t; e.tagName = t.toUpperCase(); if (t === 'button') sandbox.__btnCreated = (sandbox.__btnCreated || 0) + 1; return e; },
        // 3.0.1（#32 修复）：mountRows 用 DocumentFragment 挂载列表行
        createDocumentFragment: () => { const e = makeEl('fragment'); e.tagName = '#DOCUMENT-FRAGMENT'; e.tag = 'fragment'; return e; },
        querySelector: (s) => (s === '#dialog-body' ? makeEl('dialog-body') : null),
        querySelectorAll: () => [],
        body: makeEl('body'),
        bodyIsReal: true,
    },
    location: { href: '' },
    fetch: async () => ({ ok: false }),
};
sandbox.window = {
    addEventListener(ev, fn) { if (ev === 'DOMContentLoaded') (sandbox.__domReadyFns = sandbox.__domReadyFns || []).push(fn); },
    removeEventListener() {},
    screen: { width: 1920, height: 1080 },
    setTimeout, clearTimeout,
    __TAURI__: {
        core: { invoke: tauriInvoke },
        dialog: { open: async () => null, save: async () => null, message: async () => {}, ask: async () => true },
        window: {
            getCurrentWindow: () => ({
                setSize: async () => {}, center: async () => {}, minimize: async () => {},
                close: async () => {}, maximize: async () => {}, unmaximize: async () => {},
                isMaximized: async () => false,
                onDragDropEvent: (fn) => { sandbox.__dragRegistered = true; },
            }),
            LogicalSize: function (w, h) { this.w = w; this.h = h; },
        },
        event: { listen: async (ev, fn) => { sandbox.__listened = (sandbox.__listened || []).concat(ev); } },
        opener: { openUrl: async () => {} },
    },
};
sandbox.hideDialogSafe = () => { try { sandbox.hideDialog && sandbox.hideDialog(); } catch (e) {} };
sandbox.setImmediate = setImmediate;
sandbox.__calls = calls;
sandbox.invoke = tauriInvoke;
sandbox.state = sandbox.state || null;

vm.createContext(sandbox);
try {
    vm.runInContext(src, sandbox, { filename: 'app.js' });
} catch (e) {
    console.log('TOP-LEVEL ERROR:', e.message);
    process.exit(1);
}

(async () => {
    try {
        const fns = sandbox.__domReadyFns || [];
        for (const fn of fns) await fn();
        setTimeout(() => {}, 0);
        await new Promise(r => setImmediate(r));
        await new Promise(r => setImmediate(r));
        const listened = sandbox.__listened || [];
        const ok = [];
        // 3.0.1（#33 修复）：「启动弹窗已显示」由永真式（? true : true）改为
        // 真实可观测信号 —— showStartupModal() 的类副作用 + 启动列表真实渲染
        const sd = $('startup-dialog');
        ok.push(['startup modal shown (no hidden + overlay modal + body has-modal)',
            !sd.classList.contains('hidden')
            && $('overlay').classList.contains('startup-modal')
            && sandbox.document.body.classList.contains('has-modal')]);
        ok.push(['startup list rendered 1 item', $('startup-list').children.length === 1]);
        ok.push(['drag-drop registered', sandbox.__dragRegistered === true]);
        ok.push(['event listeners', (listened.includes('vault-file-requested') && listened.includes('vault-locked') && listened.includes('import-progress'))]);

        // ── 胁迫密码 / 硬件密钥按钮完整链路（vm 内执行，返回结果数组）──
        const uiResults = vm.runInContext(`(async () => {
            const out = [];
            try {
                state.vaultOpen = true;
                $('btn-duress').onclick();
                await new Promise(r => setImmediate(r));
                await new Promise(r => setImmediate(r));
                out.push(['duress dialog opened', $('dialog-title').textContent.includes('胁迫')]);
                const btns = [...$('dialog-buttons').querySelectorAll('button')];
                const flowNew = btns.find(b => b.textContent.includes('新建胁迫分区'));
                out.push(['duress buttons present', !!flowNew && btns.length >= 3]);
                if (flowNew) {
                    flowNew.click();
                    await new Promise(r => setImmediate(r));
                    await new Promise(r => setImmediate(r));
                    const sub = [...$('dialog-buttons').querySelectorAll('button')];
                    out.push(['duress sub-dialog clickable', sub.length >= 2 && sub.every(b => !b.disabled)]);
                }
                hideDialogSafe();
                $('btn-yk').onclick();
                await new Promise(r => setImmediate(r));
                await new Promise(r => setImmediate(r));
                out.push(['yubikey dialog opened', $('dialog-title').textContent.includes('硬件密钥')]);
                const yb = [...$('dialog-buttons').querySelectorAll('button')];
                const ykEnable = yb.find(b => b.textContent.includes('启用'));
                if (ykEnable) {
                    ykEnable.click();
                    await new Promise(r => setImmediate(r));
                    await new Promise(r => setImmediate(r));
                    const sub = [...$('dialog-buttons').querySelectorAll('button')];
                    out.push(['yubikey sub-dialog clickable', sub.length >= 2 && sub.every(b => !b.disabled)]);
                }
                hideDialogSafe();
            } catch (e) {
                out.push(['UI chain exception: ' + e.message, false]);
            }
            return out;
        })()`, sandbox);
        const uiOk = await uiResults;
        for (const [name, pass] of uiOk) {
            ok.push([name, pass]);
        }

        console.log('DEBUG: btnCreated=' + (sandbox.__btnCreated || 0) + ' btnAppended=' + (sandbox.__btnAppended || 0));
        // ── 回车确认密码（2.8.2 P2-20 功能回归守卫）──
        const enterResult = vm.runInContext(`(async () => {
            const out = [];
            let got = null;
            showInput('回车测试', '输入：', '', (v) => { got = v; return true; }, true, null);
            const inp = $('dlg-input');
            out.push(['input element exists tag=' + (inp ? inp.tagName : 'null') + ' parsed=' + (($('__parsed_count') ? 'y' : 'n')), !!inp && inp.tagName === 'INPUT']);
            inp.value = 'enter-test-password';
            // 模拟在输入框上按 Enter（IIFE 的 keydown 委托应触发 btn-ok）
                // 环节 A：直接 click 确定按钮 → action → callback
            let okBtn = $('dialog').querySelector('#dialog-buttons button.btn-ok:not(:disabled)');
            okBtn.click();
            out.push(['enter A: direct click submits', got === 'enter-test-password']);
            // 环节 B：fireKey 委托（重开密码框）
            got = null;
            showInput('回车测试B', '输入：', '', (v) => { got = v; return true; }, true, null);
            const inpB = $('dlg-input');
            inpB.value = 'enter-test-password';
            inpB.fireKey('Enter'); // 模拟用户在输入框上按回车（冒泡到 #dialog 委托）
            out.push(['enter B: fireKey delegates', got === 'enter-test-password']);
            return out;
        })()`, sandbox);
        for (const [name, pass] of await enterResult) {
            ok.push([name, pass]);
        }

        // ── 3.0.1（#32 修复）：列表渲染链冒烟 —— listFolder → renderList →
        // buildFileRow（×2 行）→ mountRows（fragment 挂载）。旧 mock 形状错误
        // 使 .map 抛错走 catch，buildFileRow 0 覆盖且冒烟 PASS。
        await vm.runInContext("(async () => { await listFolder('/'); })()", sandbox);
        {
            const fl = $('file-list');
            const frag = fl.children[0];
            ok.push(['list rendering chain (buildFileRow x2 mounted)',
                fl.children.length === 1 && frag && frag.children && frag.children.length === 2
                && frag.children[0].className === 'file-item']);
        }

        console.log('DEBUG: parsed inputs =', sandbox.__parsed || 0);
        let fail = false;
        for (const [name, pass] of ok) {
            console.log((pass ? 'PASS' : 'FAIL') + ': ' + name);
            if (!pass) fail = true;
        }
        process.exit(fail ? 1 : 0);
    } catch (e) {
        console.log('RUNTIME ERROR in init chain:', e.stack ? e.stack.split('\n').slice(0, 6).join('\n') : e.message);
        process.exit(1);
    }
})();
