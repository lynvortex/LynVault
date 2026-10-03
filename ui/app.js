// LynVault 2.0 - Tauri Frontend
// 等 Tauri 注入完毕再执行
let invoke, tauriOpen, tauriSave, tauriMessage, tauriAsk;

function initTauri() {
    // 诊断信息
    const hasTauri = !!window.__TAURI__;
    const hasInternals = !!window.__TAURI_INTERNALS__;
    const tauriKeys = hasTauri ? Object.keys(window.__TAURI__).join(', ') : 'N/A';
    const internalsKeys = hasInternals ? Object.keys(window.__TAURI_INTERNALS__).join(', ') : 'N/A';
    console.log('[LynVault] __TAURI__:', hasTauri, tauriKeys);
    console.log('[LynVault] __TAURI_INTERNALS__:', hasInternals, internalsKeys);

    try {
        if (window.__TAURI__ && window.__TAURI__.tauri && window.__TAURI__.tauri.invoke) {
            invoke = window.__TAURI__.tauri.invoke;
            tauriOpen = window.__TAURI__.dialog.open;
            tauriSave = window.__TAURI__.dialog.save;
            tauriMessage = window.__TAURI__.dialog.message;
            tauriAsk = window.__TAURI__.dialog.ask;
            console.log('[LynVault] API via __TAURI__');
            return true;
        }
    } catch (e) { console.warn('__TAURI__ failed:', e); }

    try {
        if (window.__TAURI_INTERNALS__ && window.__TAURI_INTERNALS__.invoke) {
            invoke = window.__TAURI_INTERNALS__.invoke;
            tauriOpen = (opts) => invoke('plugin:dialog|open', opts || {});
            tauriSave = (opts) => invoke('plugin:dialog|save', opts || {});
            tauriMessage = (msg, opts) => invoke('plugin:dialog|message', { message: msg, ...(opts || {}) });
            tauriAsk = (msg, opts) => invoke('plugin:dialog|ask', { message: msg, ...(opts || {}) });
            console.log('[LynVault] API via __TAURI_INTERNALS__');
            return true;
        }
    } catch (e) { console.warn('__TAURI_INTERNALS__ failed:', e); }

    // 显示诊断信息在页面上
    document.body.innerHTML = '<div style="padding:40px;font-family:monospace">' +
        '<h3>Tauri API 诊断</h3>' +
        '<p>__TAURI__: ' + hasTauri + ' → [' + tauriKeys + ']</p>' +
        '<p>__TAURI_INTERNALS__: ' + hasInternals + ' → [' + internalsKeys + ']</p>' +
        '<p>请打开 F12 控制台查看详细日志，截图反馈给开发者。</p>' +
        '</div>';
    return false;
}

// ───────────────── 状态 ─────────────────
const state = {
    vaultOpen: false,
    currentFolder: '/',
    selectedItems: [],
    searchMode: false, // 2.8.0：当前列表为搜索结果（清空搜索或导航后恢复目录视图）
};

// ───────────────── 2.8.0：设置（持久化） ─────────────────
let settingsEnabled = false;
let appSettings = { theme: 'blue', autolock_minutes: 2, window_width: 960, window_height: 620, anti_screenshot: true };

async function loadSettings() {
    try {
        const raw = await invoke('get_settings');
        settingsEnabled = !!raw.enabled;
        if (raw.settings) appSettings = raw.settings;
        applyTheme(appSettings.theme);
    } catch (e) {
        console.warn('[LynVault] 读取设置失败（使用默认值）:', e);
    }
}

const KNOWN_THEMES = ['blue', 'purple', 'gold', 'cyan'];
function applyTheme(name) {
    document.body.classList.remove(...KNOWN_THEMES.map(t => 'theme-' + t));
    const theme = KNOWN_THEMES.includes(name) ? name : 'blue';
    document.body.classList.add('theme-' + theme);
}

function applyWindowSize(w, h) {
    try {
        const tw = window.__TAURI__ && window.__TAURI__.window;
        if (!tw) return;
        const appWin = tw.getCurrent();
        if (tw.LogicalSize) appWin.setSize(new tw.LogicalSize(w, h));
        else appWin.setSize({ width: w, height: h });
        appWin.center();
    } catch (e) { console.warn('[LynVault] 应用窗口尺寸失败:', e); }
}

// ───────────────── DOM ─────────────────
const $ = id => document.getElementById(id);

// ───────────────── 工具函数 ─────────────────
function toggleUI(open) {
    state.vaultOpen = open;
    // 2.5.1：新建文件夹重新加入工具栏（右键菜单入口保留）
    // 2.8.0：修改密码 / 操作记录 / 完整性体检 同为开柜后可用
    const ids = ['btn-close', 'btn-add-part', 'btn-del-part', 'btn-import-file',
        'btn-import-folder', 'btn-newfolder', 'btn-extract-all', 'btn-defrag', 'btn-destroy',
        'btn-change-pwd', 'btn-audit', 'btn-verify'];
    ids.forEach(id => { const el = $(id); if (el) el.disabled = !open; });
    $('btn-create').disabled = open;
    $('btn-open').disabled = open;
    const nav = $('nav');
    if (open) nav.classList.remove('hidden');
    else nav.classList.add('hidden');
    if (!open) {
        $('file-list').innerHTML = '';
        state.selectedItems = [];
        state.currentFolder = '/';
        $('path-input').value = '/';
        // 2.8.0：清空搜索状态
        state.searchMode = false;
        const si = $('search-input');
        if (si) si.value = '';
        // 2.8.0：关闭后停掉空闲计时（等下次开柜再启动）
        if (_idleTimer) { clearTimeout(_idleTimer); _idleTimer = null; }
    } else {
        // 2.8.0：开柜即启动空闲自动锁定计时
        resetIdleTimer();
    }
}

function setStatus(msg) {
    $('status-bar').textContent = msg;
}

function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
    return (bytes / 1073741824).toFixed(2) + ' GB';
}

function getIcon(name, isFolder) {
    if (isFolder) return '📁';
    const ext = name.split('.').pop().toLowerCase();
    const map = {
        'png': '🖼️', 'jpg': '🖼️', 'jpeg': '🖼️', 'gif': '🖼️', 'bmp': '🖼️', 'webp': '🖼️',
        'mp4': '🎬', 'mkv': '🎬', 'avi': '🎬', 'mov': '🎬',
        'mp3': '🎵', 'wav': '🎵', 'flac': '🎵', 'aac': '🎵',
        'zip': '📦', 'rar': '📦', '7z': '📦', 'tar': '📦', 'gz': '📦',
        'txt': '📄', 'md': '📄', 'log': '📄',
        'doc': '📝', 'docx': '📝', 'xls': '📊', 'xlsx': '📊',
        'pdf': '📕', 'html': '🌐', 'css': '🌐', 'js': '⚙️',
    };
    return map[ext] || '📄';
}

// 扩展名 → 系统图标 data URL 缓存（对齐 1.3.4 QFileIconProvider）
// 仅 Windows 后端返回非空 data URL；其他平台返回空串 → fallback 到 emoji
const _sysIconCache = new Map();       // ext -> dataUrl | ''
const _sysIconPending = new Map();     // ext -> Promise
// 2.5.1 修复：缓存条目上限。恶意/极端目录可包含海量不同扩展名，
// 每条 data URL 数 KB，无上限时会持续膨胀 WebView 内存；超限按 FIFO 淘汰。
const SYS_ICON_CACHE_MAX = 128;

function sysIconCacheSet(ext, v) {
    if (_sysIconCache.size >= SYS_ICON_CACHE_MAX) {
        // Map 迭代顺序 = 插入顺序，删最旧条目
        const oldest = _sysIconCache.keys().next().value;
        if (oldest !== undefined) _sysIconCache.delete(oldest);
    }
    _sysIconCache.set(ext, v);
}

// 2.6.1 新增（Linux 对齐）：非 Windows 平台后端没有系统图标
// （get_file_icon 走 #[cfg(not(windows))] 分支返回空串），文件列表只剩 emoji。
// 这里提供一套内置 SVG 文件类型图标做兜底，使 Linux 观感与 Windows 一致。
// 仅在「非 Windows」且后端返回空时启用：Windows 仍使用真实系统图标或原有
// emoji 兜底，行为完全不变（不引入任何 Rust 侧改动与平台依赖）。
const IS_WINDOWS = /Windows/i.test(navigator.userAgent || '');

// [扩展名列表, 角标文字(≤3 字符), 底色]
const BUILTIN_ICON_CATEGORIES = [
    [['pdf'], 'PDF', '#e04646'],
    [['doc', 'docx', 'rtf', 'odt'], 'DOC', '#2f7cf6'],
    [['xls', 'xlsx', 'csv', 'ods'], 'XLS', '#21a366'],
    [['ppt', 'pptx', 'odp'], 'PPT', '#e06c2b'],
    [['png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'svg', 'ico', 'tif', 'tiff'], 'IMG', '#7c5cff'],
    [['mp4', 'mkv', 'avi', 'mov', 'wmv', 'flv', 'webm'], 'VID', '#ff5c8a'],
    [['mp3', 'wav', 'flac', 'aac', 'ogg', 'm4a'], 'AUD', '#ff9f43'],
    [['zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz'], 'ZIP', '#ffb020'],
    [['txt', 'md', 'log'], 'TXT', '#8a94a6'],
    [['js', 'ts', 'jsx', 'tsx', 'json', 'html', 'css', 'rs', 'py', 'java', 'c', 'cpp', 'h', 'go', 'sh', 'xml', 'yml', 'yaml'], '&lt;/&gt;', '#6b7bd6'],
];

const _builtinIconCache = new Map();   // ext -> data URL

function builtinIconDataUrl(ext) {
    if (_builtinIconCache.has(ext)) return _builtinIconCache.get(ext);
    const hit = BUILTIN_ICON_CATEGORIES.find(c => c[0].indexOf(ext) >= 0);
    const label = hit ? hit[1] : '?';
    const color = hit ? hit[2] : '#8a94a6';
    const svg =
        '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 48 48">' +
        '<rect x="4" y="4" width="40" height="40" rx="9" fill="' + color + '"/>' +
        '<text x="24" y="25" text-anchor="middle" dominant-baseline="central" ' +
        'font-family="Segoe UI,Roboto,DejaVu Sans,sans-serif" font-size="14" font-weight="700" ' +
        'fill="#ffffff">' + label + '</text></svg>';
    const url = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svg);
    if (_builtinIconCache.size >= SYS_ICON_CACHE_MAX) {
        const oldest = _builtinIconCache.keys().next().value;
        if (oldest !== undefined) _builtinIconCache.delete(oldest);
    }
    _builtinIconCache.set(ext, url);
    return url;
}

async function getSysIconDataUrl(name) {
    if (!invoke) return '';
    const dot = name.lastIndexOf('.');
    if (dot < 0) return '';
    const ext = name.slice(dot + 1).toLowerCase();
    if (!ext || ext.length > 32) return '';

    if (_sysIconCache.has(ext)) return _sysIconCache.get(ext);
    if (_sysIconPending.has(ext)) return _sysIconPending.get(ext);

    const p = (async () => {
        try {
            const dataUrl = await invoke('get_file_icon', { ext });
            let v = typeof dataUrl === 'string' ? dataUrl : '';
            // 2.6.1：非 Windows 后端返回空 → 内置 SVG 图标兜底
            if (!v && !IS_WINDOWS) v = builtinIconDataUrl(ext);
            sysIconCacheSet(ext, v);
            return v;
        } catch (e) {
            const v = IS_WINDOWS ? '' : builtinIconDataUrl(ext);
            sysIconCacheSet(ext, v);
            return v;
        } finally {
            _sysIconPending.delete(ext);
        }
    })();
    _sysIconPending.set(ext, p);
    return p;
}

// 给文件项图标元素异步替换为系统图标
async function applySysIcon(spanEl, name, fallbackEmoji) {
    spanEl.textContent = fallbackEmoji;
    try {
        const url = await getSysIconDataUrl(name);
        if (url) {
            spanEl.innerHTML = '';
            const img = document.createElement('img');
            img.src = url;
            img.className = 'fi-sysicon';
            img.alt = '';
            spanEl.appendChild(img);
        }
    } catch (e) { /* keep emoji */ }
}

// ───────────────── 模态框 ─────────────────

// N3 修复：支持"不立即关闭对话框"的按钮（用于密码框异步验证后再关闭）
// Q6 修复：异步 action 执行期间禁用所有按钮，防止重复点击触发多次 invoke
function showDialog(title, bodyHtml, buttons, wide) {
    const dlg = $('dialog');
    // M10 修复：打开新对话框前清理上一个对话框的 blob URL，防止内存泄漏
    cleanupDialogBlobs();
    dlg.style.width = wide ? '80vw' : '';
    dlg.style.maxWidth = wide ? '900px' : '';
    $('dialog-title').textContent = title;
    $('dialog-body').innerHTML = bodyHtml;
    const btnContainer = $('dialog-buttons');
    btnContainer.innerHTML = '';
    buttons.forEach(b => {
        const btn = document.createElement('button');
        btn.textContent = b.text;
        if (b.cls) btn.className = b.cls;
        btn.onclick = () => {
            // Q6 修复：异步 action 期间禁用所有按钮，防止重复点击
            if (b.action) {
                // N3 修复：如果 action 返回 false 或 Promise<false>，则不关闭对话框
                // 用于密码错误后保留密码框让用户重试
                const ret = b.action();
                if (ret && typeof ret.then === 'function') {
                    // 异步执行期间禁用按钮
                    const allBtns = btnContainer.querySelectorAll('button');
                    allBtns.forEach(x => x.disabled = true);
                    ret.then(shouldClose => {
                        if (shouldClose === false) {
                            // 重试：重新启用按钮
                            allBtns.forEach(x => x.disabled = false);
                        } else {
                            _activeCancelHandler = null;
                            hideDialog();
                        }
                    }).catch(() => {
                        // 异常：重新启用按钮让用户重试
                        allBtns.forEach(x => x.disabled = false);
                    });
                } else if (ret !== false) {
                    _activeCancelHandler = null;
                    hideDialog();
                }
            } else {
                hideDialog();
            }
        };
        btnContainer.appendChild(btn);
    });
    // N9 修复：overlay.onclick 只在启动弹窗未显示时绑定 hideDialog
    // 启动弹窗显示时点击遮罩不关闭任何东西（保持不可关闭语义）
    if (!$('startup-dialog').classList.contains('hidden')) {
        $('overlay').onclick = null;
    } else {
        $('overlay').onclick = hideDialog;
    }
    $('overlay').classList.remove('hidden');
    $('dialog').classList.remove('hidden');
}

// M10 修复：追踪并释放 blob URL，避免图片预览内存泄漏
let _activeBlobUrls = [];
function cleanupDialogBlobs() {
    for (const url of _activeBlobUrls) {
        try { URL.revokeObjectURL(url); } catch (e) { /* ignore */ }
    }
    _activeBlobUrls = [];
}

function hideDialog() {
    const dlg = $('dialog');
    // 2.8.1：清空对话框内容 —— 密码输入框等明文不允许残留在 DOM 中
    //（场景：锁屏触发的 vault-locked 会强制关闭正在输入的对话框）
    $('dialog-title').textContent = '';
    $('dialog-body').innerHTML = '';
    $('dialog-buttons').innerHTML = '';
    // 关闭对话框等同于放弃当前输入：触发挂起的取消回调（见 showInput）
    if (_activeCancelHandler) {
        const h = _activeCancelHandler;
        _activeCancelHandler = null;
        try { h(); } catch (e) { /* ignore */ }
    }
    dlg.style.width = '';
    dlg.style.height = '';
    dlg.style.maxWidth = '';
    dlg.style.left = '';
    dlg.style.top = '';
    dlg.style.transform = 'translate(-50%, -50%)';
    // 仅在启动弹窗未显示时才隐藏 overlay
    // 否则会把启动弹窗的灰色遮罩一起隐藏
    if ($('startup-dialog').classList.contains('hidden')) {
        $('overlay').classList.add('hidden');
    }
    dlg.classList.add('hidden');
    // M10 修复：关闭对话框时释放 blob URL
    cleanupDialogBlobs();
}

// ── 四向拖拽调整大小 ──
(function initDialogResize() {
    const dlg = $('dialog');
    let startX, startY, startW, startH, startLeft, startTop, dir;

    dlg.addEventListener('mousedown', function(e) {
        const handle = e.target.closest('.dialog-resize');
        if (!handle) return;
        e.preventDefault();
        dir = handle.dataset.dir;
        startX = e.clientX;
        startY = e.clientY;
        const rect = dlg.getBoundingClientRect();
        startW = rect.width;
        startH = rect.height;
        startLeft = rect.left;
        startTop = rect.top;
        // 切换为左上角定位
        dlg.style.transform = 'none';
        dlg.style.left = startLeft + 'px';
        dlg.style.top = startTop + 'px';
        document.addEventListener('mousemove', onResize);
        document.addEventListener('mouseup', onStopResize);
    });

    function onResize(e) {
        const dx = e.clientX - startX;
        const dy = e.clientY - startY;
        let newW = startW, newH = startH, newL = startLeft, newT = startTop;

        if (dir.includes('e')) newW = startW + dx;
        if (dir.includes('w')) { newW = startW - dx; newL = startLeft + dx; }
        if (dir.includes('s')) newH = startH + dy;
        if (dir.includes('n')) { newH = startH - dy; newT = startTop + dy; }

        // 最小尺寸
        if (newW < 320) { if (dir.includes('w')) newL = startLeft + startW - 320; newW = 320; }
        if (newH < 120) { if (dir.includes('n')) newT = startTop + startH - 120; newH = 120; }

        dlg.style.width = newW + 'px';
        dlg.style.height = newH + 'px';
        dlg.style.left = newL + 'px';
        dlg.style.top = newT + 'px';
    }

    function onStopResize() {
        document.removeEventListener('mousemove', onResize);
        document.removeEventListener('mouseup', onStopResize);
    }
})();

// HTML 转义工具函数（M4 修复：防止 XSS）
function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function(c) {
        return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c] || c;
    });
}

// 构造属性值（用双引号包裹，转义 & < > "）
function escapeAttr(s) {
    return String(s).replace(/[&<>"]/g, function(c) {
        return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c] || c;
    });
}

// 2.8.1：当前对话框的取消回调（showInput 注册）。遮罩点击触发的 hideDialog
// 现在会触发它 —— 修复启动密码框阶段点遮罩导致 _startupProcessing 卡死的软锁死
let _activeCancelHandler = null;

// 2.4.1：bytesToBase64 已删除 —— load_file_content 后端直接返回 base64 字符串，
// 前端不再需要手工转换（也避免了旧实现对大文件的字符串拼接开销）。

// R1 修复：增加 onCancel 回调。取消按钮显式调用 onCancel，
// 确保启动弹窗流程的状态标志 (_startupProcessing) 总能被重置。
// R2 修复：密码错误时调用 onInlineError 而非 showError，
// 在密码框下方显示错误，不销毁密码输入框 DOM，让用户可重试。
// Q7 修复：密码错误时清空输入框，避免用户直接点确定又错一次
function showInput(title, label, defaultValue, callback, isPassword, onCancel) {
    const type = isPassword ? 'password' : 'text';
    // M4 修复：转义 label 和 defaultValue，防止 XSS
    // N3 修复：callback 返回 false 时不关闭对话框（密码错误可重试）
    showDialog(title,
        `<label>${escapeHtml(label)}</label><input type="${type}" id="dlg-input" value="${escapeAttr(defaultValue || '')}"><div id="dlg-input-error" style="color:#ff6666;font-size:12px;margin-top:4px;min-height:14px;"></div>` +
        // 2.8.0：开锁前提示位（get_lock_info 异步填充失败尝试次数）
        `<div id="dlg-lock-hint" style="color:#8a6d1a;font-size:12px;margin-top:2px;min-height:0;"></div>`,
        [
            { text: '确定', cls: 'btn-ok', action: () => callback($('dlg-input').value) },
            { text: '取消', cls: 'btn-cancel', action: () => { if (onCancel) onCancel(); } }
        ]
    );
    // 2.8.1：注册取消回调 —— 遮罩点击关对话框时同样触发（回调内部自带
    // 重置 _startupProcessing / 重弹启动窗的逻辑）
    _activeCancelHandler = onCancel || null;
    setTimeout(() => { const inp = $('dlg-input'); if (inp) { inp.focus(); inp.select(); } }, 50);
}

// 2.8.0：异步查询保险柜头部锁定区的失败尝试计数，填充到密码框提示位。
// 让用户在开锁前看到「这个文件已被试错 N 次」—— 察觉有人动过自己的保险柜。
function fetchLockHint(filePath) {
    invoke('get_lock_info', { path: filePath }).then(info => {
        const el = $('dlg-lock-hint');
        if (!el || !info) return;
        if (info.locked) {
            const until = new Date((info.lockUntilEpoch || 0) * 1000).toLocaleTimeString('zh-CN');
            el.textContent = `⛔ 已因连续 ${info.failedCount} 次错误尝试锁定，至 ${until}`;
        } else if (info.failedCount > 0) {
            el.textContent = `⚠ 该保险柜已记录 ${info.failedCount} 次解锁失败尝试`;
        }
    }).catch(() => { /* 锁定区损坏等错误不打断密码输入流程 */ });
}

// R2 修复：在密码框内联显示错误，不销毁密码框 DOM
// Q7 修复：同时清空密码输入框，避免用户直接点确定又错一次
function showInlineInputError(msg) {
    const el = $('dlg-input-error');
    if (el) {
        el.textContent = msg;
    } else {
        // fallback：如果找不到内联错误区域，用原生消息框（不破坏 DOM）
        try { tauriMessage(String(msg), { title: '错误', type: 'error' }); } catch (e) { /* ignore */ }
    }
    // Q7：清空输入框并重新聚焦
    const inp = $('dlg-input');
    if (inp) {
        inp.value = '';
        inp.focus();
    }
}

function showError(msg) {
    const pre = document.createElement('pre');
    pre.style.color = '#ff6666';
    pre.textContent = msg;
    showDialog('错误', pre.outerHTML, [{ text: '确定', cls: 'btn-ok' }]);
}

// ───────────────── 右键菜单（2.3.0 起动态构建）─────────────────
// 文件/文件夹右键：打开/查看、提取（支持多选）、重命名、安全删除（支持多选）
// 空白区右键：新建文件夹、导入文件、导入文件夹
function renderCtxMenu(items) {
    const menu = $('ctx-menu');
    menu.innerHTML = '';
    items.forEach(it => {
        if (it.sep) {
            const s = document.createElement('div');
            s.className = 'ctx-sep';
            menu.appendChild(s);
        } else {
            const d = document.createElement('div');
            d.dataset.act = it.act;
            d.textContent = it.label;
            if (it.danger) d.className = 'danger';
            menu.appendChild(d);
        }
    });
    return menu;
}

// 显示菜单并防止溢出窗口边缘
function positionMenu(x, y) {
    const menu = $('ctx-menu');
    menu.classList.remove('hidden');
    const rect = menu.getBoundingClientRect();
    const vw = window.innerWidth, vh = window.innerHeight;
    const mx = Math.max(4, Math.min(x, vw - rect.width - 4));
    const my = Math.max(4, Math.min(y, vh - rect.height - 4));
    menu.style.left = mx + 'px';
    menu.style.top = my + 'px';
}

function showItemMenu(x, y, item, count) {
    const isFolder = item.type === 'folder';
    const items = [
        { act: 'open', label: isFolder ? '打开文件夹' : '安全查看' },
        { act: 'extract', label: count > 1 ? `提取（${count} 项）` : '提取' },
        { act: 'move', label: count > 1 ? `移动到…（${count} 项）` : '移动到…' },
        { act: 'rename', label: '重命名', sep: true },
        { act: 'delete', label: count > 1 ? `安全删除（${count} 项）` : '安全删除', danger: true },
    ];
    const menu = renderCtxMenu(items);
    menu._item = item;
    menu._context = 'item';
    positionMenu(x, y);
}

function showBlankMenu(x, y) {
    const items = [
        { act: 'select-all', label: state.selectedItems.length > 0 ? `全选（${state.selectedItems.length} 项已选）` : '全选' },
        { act: 'new-folder', label: '新建文件夹', sep: true },
        { act: 'import-file', label: '导入文件' },
        { act: 'import-folder', label: '导入文件夹' },
    ];
    const menu = renderCtxMenu(items);
    menu._item = null;
    menu._context = 'blank';
    positionMenu(x, y);
}

function hideCtxMenu() {
    $('ctx-menu').classList.add('hidden');
}

// ───────────────── 列表渲染 ─────────────────
// 2.8.1（性能）：共享行构建 + DocumentFragment + 事件委托。
// 旧实现每项 3 个闭包 + 逐项 appendChild（2000 项 ≈ 6000 闭包、整页回流多次），
// 现在每项一次 innerHTML 构建进 fragment、一次挂载，交互事件统一委托到 #file-list。
function buildFileRow(f) {
    const isFolder = f.type === 'folder';
    const div = document.createElement('div');
    div.className = 'file-item';
    div.dataset.vpath = f.vpath;
    div.dataset.type = f.type;
    div.dataset.name = f.name;
    const fallbackEmoji = isFolder ? '📁' : getIcon(f.name, false);
    div.innerHTML = `<span class="fi-icon"></span><span class="fi-name">${escapeHtml(f.name)}</span><span class="fi-size">${isFolder ? '-' : formatSize(f.size)}</span>`;
    const iconSpan = div.querySelector('.fi-icon');
    if (isFolder) {
        iconSpan.textContent = fallbackEmoji;
    } else {
        applySysIcon(iconSpan, f.name, fallbackEmoji);
    }
    return div;
}

function mountRows(rows, emptyHintHtml) {
    const list = $('file-list');
    list.innerHTML = '';
    state.selectedItems = [];
    if (!rows.length) {
        list.innerHTML = emptyHintHtml;
        return;
    }
    const frag = document.createDocumentFragment();
    rows.forEach(r => frag.appendChild(r));
    list.appendChild(frag);
}

function renderList(data) {
    const rows = (data || []).map(f => buildFileRow(f));
    mountRows(rows, '<div class="empty-hint">' +
        '<svg width="45" height="55" viewBox="0 0 45 55" fill="none" style="display:block;margin:0 auto 12px auto;opacity:0.5">' +
        '<path d="M0 0H33L45 12V55H0Z" fill="#a0a0a0"/>' +
        '<path d="M33 0V12H45Z" fill="#828282"/>' +
        '</svg>' +
        '<span>将文件拖放至此（右键可新建文件夹 / 导入）</span>' +
        '</div>');
}

// 事件委托：单次绑定，取代旧 per-item 闭包（点击选择 / 双击打开 / 右键菜单）
function bindListDelegation() {
    const list = $('file-list');
    list.addEventListener('click', (e) => {
        const el = e.target.closest('.file-item');
        if (el) selectItem(el, e);
    });
    list.addEventListener('dblclick', (e) => {
        const el = e.target.closest('.file-item');
        if (!el) return;
        if (el.dataset.type === 'folder') navigateTo(el.dataset.vpath);
        else viewFile(el.dataset.vpath, el.dataset.name);
    });
    list.addEventListener('contextmenu', (e) => {
        const el = e.target.closest('.file-item');
        if (!el) return;
        e.preventDefault();
        e.stopPropagation(); // 防止触发空白区菜单
        // 2.3.0：若该条目已在多选中，保留整组选择（提取/删除作用于全部选中项）；
        // 否则仅选中该条目
        if (!el.classList.contains('selected')) {
            selectItem(el, e);
        }
        showItemMenu(e.clientX, e.clientY, { vpath: el.dataset.vpath, type: el.dataset.type, name: el.dataset.name }, state.selectedItems.length);
    });
}

function selectItem(el, e) {
    if (!e.ctrlKey && !e.metaKey) {
        document.querySelectorAll('.file-item.selected').forEach(d => d.classList.remove('selected'));
        state.selectedItems = [];
    }
    el.classList.toggle('selected');
    const item = { vpath: el.dataset.vpath, type: el.dataset.type, name: el.dataset.name };
    if (el.classList.contains('selected')) {
        state.selectedItems.push(item);
    } else {
        state.selectedItems = state.selectedItems.filter(s => s.vpath !== item.vpath);
    }
    const count = state.selectedItems.length;
    setStatus(count > 0 ? `已选中 ${count} 个项目` : '就绪');
}

// 2.3.0 新增：全选当前目录下的所有文件/文件夹
function selectAllItems() {
    const items = document.querySelectorAll('#file-list .file-item');
    if (!items.length) return;
    items.forEach(d => d.classList.add('selected'));
    state.selectedItems = Array.from(items).map(d => ({
        vpath: d.dataset.vpath,
        type: d.dataset.type,
        name: d.dataset.name,
    }));
    setStatus(`已选中 ${state.selectedItems.length} 个项目`);
}

// ───────────────── 核心操作 ─────────────────

// 2.7.1 修复：路径框输入先按与后端一致的规则归一化再进入列表，
// state.currentFolder 存储的始终是实际显示的目录（后端 list_folder 已按
// 归一化目录返回内容，旧实现存原始输入导致状态与显示不一致）
function normalizeVPath(v) {
    if (typeof v !== 'string' || v.includes('\\') || v.includes('\0')) return null;
    const parts = [];
    for (const seg of v.split('/')) {
        if (!seg || seg === '.') continue;
        if (seg === '..') { parts.pop(); continue; }
        parts.push(seg);
    }
    return '/' + parts.join('/');
}

async function listFolder(folder) {
    const norm = normalizeVPath(folder);
    if (!norm) {
        showError('无效的目录路径');
        return;
    }
    // 2.8.0：目录导航会覆盖搜索视图
    state.searchMode = false;
    const si = $('search-input');
    if (si && si.value) si.value = '';
    try {
        const raw = await invoke('list_folder', { folder: norm });
        const data = typeof raw === 'string' ? JSON.parse(raw) : raw;
        state.currentFolder = norm;
        $('path-input').value = norm;
        renderList(data);
        setStatus(`共 ${data.length} 个项目`);
    } catch (e) {
        showError(String(e));
    }
}

async function navigateTo(vpath) {
    await listFolder(vpath);
}

async function createVault() {
    const filePath = await tauriSave({
        title: '选择保险柜保存位置',
        filters: VAULT_FILTERS,
    });
    if (!filePath) return;
    showInput('创建保险柜', '输入主密码：', '', async (pwd) => {
        if (!pwd) {
            // 2.7.1 修复：空密码点确定不再静默关闭对话框 —— 内联提示并保留
            // 输入框，与启动弹窗路径行为一致
            showInlineInputError('密码不能为空');
            return false;
        }
        try {
            await invoke('create_vault', { path: filePath, password: pwd, keyFilePath: null });
            toggleUI(true);
            await listFolder('/');
            setStatus('保险柜已创建');
            return true;
        } catch (e) {
            showInlineInputError(String(e));
            return false; // R2 修复：内联错误，保留密码框重试
        }
    }, true);
}

async function openVault() {
    const filePath = await tauriOpen({
        title: '选择保险柜文件',
        filters: VAULT_OPEN_FILTERS,
    });
    if (!filePath) return;
    showInput('打开保险柜', '输入主密码：', '', async (pwd) => {
        if (!pwd) {
            // 2.7.1：与创建路径一致，空密码内联提示并保留输入框
            showInlineInputError('密码不能为空');
            return false;
        }
        try {
            await invoke('open_vault', { path: filePath, password: pwd, keyFilePath: null });
            toggleUI(true);
            await listFolder('/');
            setStatus('保险柜已打开');
            return true;
        } catch (e) {
            showInlineInputError(String(e));
            return false; // R2 修复：内联错误，保留密码框重试
        }
    }, true);
    // 2.8.0：开锁前展示该保险柜的历史失败尝试次数
    fetchLockHint(filePath);
}

async function closeVault() {
    try {
        await invoke('close_vault');
        toggleUI(false);
        setStatus('保险柜已关闭');
    } catch (e) {
        showError(String(e));
    }
}

async function importFiles() {
    const files = await tauriOpen({ title: '选择要导入的文件', multiple: true });
    if (!files || files.length === 0) return;
    const fileList = Array.isArray(files) ? files : [files];
    setStatus(`正在导入 ${fileList.length} 个文件...`);
    try {
        // 2.4.1：改为后端批量导入（单次索引加密落盘），
        // 旧版前端循环 import_file 会对每个文件全量重写一次索引
        const raw = await invoke('import_files_batch', {
            srcPaths: fileList,
            destBase: state.currentFolder,
        });
        const res = typeof raw === 'string' ? JSON.parse(raw) : raw;
        await listFolder(state.currentFolder);
        setStatus(res.fail > 0
            ? `导入完成: 成功 ${res.ok} 个，失败 ${res.fail} 个`
            : `导入完成: ${res.ok} 个文件`);
    } catch (e) {
        showError(String(e));
        await listFolder(state.currentFolder);
    }
}

async function importFolder() {
    const folder = await tauriOpen({ title: '选择要导入的文件夹', directory: true });
    if (!folder) return;
    setStatus('正在导入文件夹...');
    try {
        await invoke('import_folder', { srcFolder: folder, destBase: state.currentFolder });
        await listFolder(state.currentFolder);
        setStatus('文件夹导入完成');
    } catch (e) {
        showError(String(e));
        await listFolder(state.currentFolder);
    }
}

async function extractSelected() {
    if (!state.selectedItems.length) return;
    const dest = await tauriOpen({ title: '选择提取目标文件夹', directory: true });
    if (!dest) return;
    setStatus('正在提取...');
    try {
        const vpaths = state.selectedItems.map(i => i.vpath);
        // 2.7.1：后端返回 {ok, fail}，失败数不再被静默丢弃
        const raw = await invoke('extract_files', { vpaths, destFolder: dest });
        const res = typeof raw === 'string' ? JSON.parse(raw) : raw;
        setStatus(res.fail > 0
            ? `提取完成: 成功 ${res.ok} 个，失败 ${res.fail} 个 → ${dest}`
            : `提取完成: ${res.ok} 个文件 → ${dest}`);
    } catch (e) {
        showError(String(e));
    }
}

async function extractAllFiles() {
    // 提取全部：选择父目录，后端会在其下创建与保险柜同名的子文件夹
    const dest = await tauriOpen({ title: '选择提取目标父目录（将在此创建以保险柜命名的子文件夹）', directory: true });
    if (!dest) return;

    // N8 修复：预检目标子文件夹是否已存在，存在时提示用户确认覆盖
    try {
        const checkRaw = await invoke('check_extract_all_dest', { destParentFolder: dest });
        const check = typeof checkRaw === 'string' ? JSON.parse(checkRaw) : checkRaw;
        if (check && check.exists) {
            const ok = await tauriAsk(
                `目标文件夹已存在：\n${check.dest_name}\n\n继续提取将覆盖同名文件。是否继续？`,
                { title: '确认覆盖', type: 'warning' }
            );
            if (!ok) return;
        }
    } catch (e) {
        // 预检失败不阻断流程，继续提取
        console.warn('check_extract_all_dest 失败:', e);
    }

    setStatus('正在提取全部文件...');
    try {
        const raw = await invoke('extract_all_files', { destParentFolder: dest });
        const res = typeof raw === 'string' ? JSON.parse(raw) : raw;
        if (res.fail > 0) {
            setStatus(`提取完成：成功 ${res.ok} 个，失败 ${res.fail} 个，输出到 ${res.dest}`);
        } else {
            setStatus(`提取完成：共 ${res.ok} 个文件，输出到 ${res.dest}`);
        }
    } catch (e) {
        showError(String(e));
    }
}

async function deleteSelected() {
    if (!state.selectedItems.length) return;
    const names = state.selectedItems.map(i => i.name).join('\n');
    const ok = await tauriAsk(`确认安全删除以下项目？\n\n${names}\n\n此操作不可撤销（DoD 7-pass 擦除）。`, { title: '确认删除', type: 'warning' });
    if (!ok) return;
    try {
        const vpaths = state.selectedItems.map(i => i.vpath);
        // N1 修复：delete_files 能同时处理文件和文件夹（后端 secure_delete_files_batch 展开）
        // 2.4.1：返回结构化 { files, folders }，精确反馈删除数量
        const raw = await invoke('delete_files', { vpaths });
        const res = typeof raw === 'string' ? JSON.parse(raw) : raw;
        await listFolder(state.currentFolder);
        const parts = [];
        if (res.files) parts.push(`${res.files} 个文件`);
        if (res.folders) parts.push(`${res.folders} 个文件夹`);
        let status = `已安全删除 ${parts.join('、') || '0 个项目'}`;
        // 2.7.0：死空间达到阈值时后端自动整理保险柜,提示回收量
        if (res.reclaimed) status += `，已自动整理回收 ${formatSize(res.reclaimed)}`;
        setStatus(status);
    } catch (e) {
        showError(String(e));
    }
}

async function newFolder() {
    showInput('新建文件夹', '文件夹名称：', '', async (name) => {
        if (!name) return;
        try {
            await invoke('new_folder', { vpath: state.currentFolder + '/' + name });
            await listFolder(state.currentFolder);
        } catch (e) {
            showError(String(e));
        }
    });
}

// 2.7.0：加密 Office 文档的口令输入循环。成功返回预览文本；取消返回 null
async function promptEncryptedOffice(vpath, fileName) {
    while (true) {
        const pwd = await new Promise(resolve => {
            showInput('🔒 ' + fileName, '该文档已加密，输入文档打开密码：', '', (v) => {
                resolve(v);
                return true;
            }, true, () => resolve(null));
        });
        if (!pwd) return null; // 取消或空口令
        try {
            return await invoke('preview_office_file', { vpath, password: pwd });
        } catch (e) {
            const msg = String(e);
            if (!msg.includes('密码错误')) {
                showError(msg);
                return null;
            }
            const retry = await tauriAsk('密码错误，是否重试？', { title: '口令验证失败', type: 'warning' });
            if (!retry) return null;
        }
    }
}

async function viewFile(vpath, fileName) {
    const ext = fileName.split('.').pop().toLowerCase();
    const imgExts = ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'tiff', 'tif'];
    const textExts = ['txt', 'md', 'py', 'log', 'json', 'csv', 'xml', 'ini', 'cfg', 'yaml', 'yml', 'rs', 'js', 'go', 'toml', 'html', 'css', 'sh', 'bat', 'ps1'];
    const officeExts = ['docx', 'doc', 'xlsx', 'xls'];

    try {
        if (officeExts.includes(ext)) {
            let text;
            try {
                text = await invoke('preview_office_file', { vpath, password: null });
            } catch (e) {
                if (String(e).includes('OFFICE_ENCRYPTED')) {
                    // 2.7.0：加密 Office 文档 —— 弹出口令输入框（可重试）
                    text = await promptEncryptedOffice(vpath, fileName);
                    if (text === null) return;
                } else {
                    showError(String(e));
                    return;
                }
            }
            const pre = document.createElement('pre');
            pre.textContent = text;
            showDialog('📄 ' + fileName, pre.outerHTML, [{ text: '关闭', cls: 'btn-ok' }], true);
            return;
        }

        // 2.4.1：load_file_content 改为返回 base64 字符串。
        // 旧版 Tauri 1.x 把 Vec<u8> 序列化成 JSON 数字数组（每字节 3-5 个字符），
        // 预览 5MB 图片要传几十 MB 文本；base64 只有 1.33× 膨胀。
        const b64 = await invoke('load_file_content', { vpath });

        if (imgExts.includes(ext)) {
            const imageMimeTypes = {
                png: 'image/png',
                jpg: 'image/jpeg',
                jpeg: 'image/jpeg',
                gif: 'image/gif',
                bmp: 'image/bmp',
                webp: 'image/webp',
                tif: 'image/tiff',
                tiff: 'image/tiff',
            };
            const imageUrl = `data:${imageMimeTypes[ext]};base64,${b64}`;
            const zoomId = 'img-zoom-' + Date.now();
            showDialog('🖼️ ' + fileName, `<div style="overflow:auto;max-height:60vh;text-align:center;"><img id="${zoomId}" src="${imageUrl}" style="max-width:100%;cursor:zoom-in;transition:transform 0.1s;"></div>`, [{ text: '关闭', cls: 'btn-ok' }], true);
            // 滚轮缩放
            setTimeout(() => {
                const img = document.getElementById(zoomId);
                if (!img) return;
                let scale = 1;
                img.parentElement.addEventListener('wheel', (e) => {
                    e.preventDefault();
                    scale += e.deltaY < 0 ? 0.15 : -0.15;
                    scale = Math.max(0.1, Math.min(scale, 10));
                    img.style.transform = `scale(${scale})`;
                    img.style.cursor = scale > 1 ? 'zoom-out' : 'zoom-in';
                });
            }, 50);
            return;
        }

        if (textExts.includes(ext)) {
            // 2.4.1：base64 → 字节 → UTF-8 文本
            const bin = atob(b64);
            const bytes = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
            // 2.5.1 新增：fatal 解码探测 —— 非 UTF-8 文本（如 GBK）保存会破坏
            // 原编码（替换字符 U+FFFD 固化），这类文件只读预览，不给编辑入口
            let utf8Valid = true;
            let text;
            try {
                text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
            } catch (e) {
                utf8Valid = false;
                text = new TextDecoder('utf-8').decode(bytes);
            }
            if (!utf8Valid) {
                const pre = document.createElement('pre');
                pre.textContent = text;
                showDialog('📄 ' + fileName, pre.outerHTML, [{ text: '关闭', cls: 'btn-ok' }], true);
                return;
            }
            // 2.5.1 新增：文本直接编辑。编辑上限 4 MB —— textarea 渲染超大文本
            // 会卡死 WebView（后端硬上限 64 MB）；超过则只读预览
            if (bytes.length > 4 * 1024 * 1024) {
                const pre = document.createElement('pre');
                pre.textContent = text;
                showDialog('📄 ' + fileName + '（超过 4 MB，只读预览）', pre.outerHTML,
                    [{ text: '关闭', cls: 'btn-ok' }], true);
                return;
            }
            const taId = 'txt-edit-' + Date.now();
            const ta = document.createElement('textarea');
            ta.id = taId;
            ta.className = 'txt-editor';
            ta.readOnly = true;
            ta.spellcheck = false;
            // 2.8.0：记录 vpath —— 空闲自动锁定时自动保存需要知道写回哪个文件
            ta.dataset.vpath = vpath;
            ta.dataset.original = text; // 原始内容（自动保存前判断是否有改动）
            // 内容用文本子节点承载：.value 属性不会序列化进 outerHTML，
            // 经 dialog-body.innerHTML 重建后会丢失；文本节点会被正确转义并还原
            ta.appendChild(document.createTextNode(text));

            const startEdit = () => {
                const el = document.getElementById(taId);
                if (!el) return false;
                el.readOnly = false;
                el.classList.add('editing');
                el.focus();
                // 按钮顺序与数组一致：[编辑, 保存, 关闭]
                const btns = document.querySelectorAll('#dialog-buttons button');
                if (btns[0]) btns[0].disabled = true;
                if (btns[1]) btns[1].disabled = false;
                return false; // 保持对话框打开
            };
            const saveEdit = async () => {
                const el = document.getElementById(taId);
                if (!el) return true;
                // UTF-8 编码 → 分块 base64（避免 fromCharCode 一次传超长参数栈溢出）
                const enc = new TextEncoder().encode(el.value);
                let binStr = '';
                const CHUNK = 0x8000;
                for (let i = 0; i < enc.length; i += CHUNK) {
                    binStr += String.fromCharCode.apply(null, enc.subarray(i, i + CHUNK));
                }
                try {
                    await invoke('update_file_content', { vpath, contentB64: btoa(binStr) });
                    await listFolder(state.currentFolder); // 刷新大小显示
                    setStatus('已保存：' + fileName);
                    return true; // 关闭对话框
                } catch (e) {
                    showError(String(e));
                    return false; // 保留编辑内容让用户重试
                }
            };

            showDialog('📄 ' + fileName, ta.outerHTML, [
                { text: '编辑', cls: 'btn-cancel', action: startEdit },
                { text: '保存', cls: 'btn-ok', action: saveEdit },
                { text: '关闭', cls: 'btn-cancel' },
            ], true);
            // 初始「保存」禁用，点「编辑」后启用（按钮顺序同上）
            const btns = document.querySelectorAll('#dialog-buttons button');
            if (btns[1]) btns[1].disabled = true;
            return;
        }

        showDialog('提示', '<p>暂不支持预览 .' + ext.replace(/[<>&"']/g, function(c) {
            return {'<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&#39;'}[c] || c;
        }) + ' 格式</p><p>请使用「提取选中」导出后查看。</p>', [{ text: '确定', cls: 'btn-ok' }]);
    } catch (e) {
        showError(String(e));
    }
}

async function renameSelected() {
    if (!state.selectedItems.length) return;
    const sel = state.selectedItems[0];
    showInput('重命名', '新名称：', sel.name, async (newName) => {
        if (!newName || newName === sel.name) return;
        try {
            await invoke('rename_item', { oldVpath: sel.vpath, newName, isFolder: sel.type === 'folder' });
            await listFolder(state.currentFolder);
        } catch (e) {
            showError(String(e));
        }
    });
}

async function defragmentVault() {
    try {
        const msg = await invoke('defragment_vault');
        await listFolder(state.currentFolder);
        setStatus(msg);
    } catch (e) {
        showError(String(e));
    }
}

async function addPartition() {
    const alias = await new Promise(resolve => {
        showInput('添加伪装分区', '分区别名：', '', resolve);
    });
    if (!alias) return;
    const pwd = await new Promise(resolve => {
        showInput('分区密码', '输入分区密码：', '', resolve, true);
    });
    if (!pwd) return;
    try {
        await invoke('add_partition', { alias, password: pwd, keyFilePath: null });
        setStatus('伪装分区已添加: ' + alias);
    } catch (e) {
        showError(String(e));
    }
}

async function removePartition() {
    try {
        const raw = await invoke('list_partitions');
        const partitions = typeof raw === 'string' ? JSON.parse(raw) : raw;
        if (!partitions || partitions.length === 0) {
            showDialog('提示', '<p>暂无伪装分区</p>', [{ text: '确定', cls: 'btn-ok' }]);
            return;
        }
        const options = partitions.map(p => `<option value="${escapeAttr(p.alias)}">${escapeHtml(p.alias)}</option>`).join('');
        showDialog('删除伪装分区',
            `<label>选择要删除的分区：</label><select id="dlg-part-select">${options}</select>`,
            [
                { text: '删除', cls: 'btn-ok', action: async () => {
                    const alias = $('dlg-part-select').value;
                    try {
                        await invoke('remove_partition', { alias });
                        setStatus('已删除分区: ' + alias);
                    } catch (e) { showError(String(e)); }
                }},
                { text: '取消', cls: 'btn-cancel' }
            ]
        );
    } catch (e) {
        showError(String(e));
    }
}

async function destroyVault() {
    const ok = await tauriAsk('此操作将不可逆地销毁当前保险柜及其所有数据！\n\n确定继续？', { title: '销毁保险箱', type: 'warning' });
    if (!ok) return;
    const ok2 = await tauriAsk('再次确认：销毁整个保险柜？', { title: '最终确认', type: 'error' });
    if (!ok2) return;
    try {
        await invoke('destroy_vault');
        toggleUI(false);
        setStatus('保险柜已销毁');
    } catch (e) {
        showError(String(e));
    }
}

// ───────────────── 2.8.0：文件名搜索 ─────────────────
let _searchDebounce = null;
let _searchSeq = 0; // 2.8.1：慢查询晚到不得覆盖新结果

function bindSearch() {
    const input = $('search-input');
    if (!input) return;
    input.addEventListener('input', () => {
        clearTimeout(_searchDebounce);
        _searchDebounce = setTimeout(runSearch, 300);
    });
    input.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            input.value = '';
            runSearch();
        } else if (e.key === 'Enter') {
            clearTimeout(_searchDebounce);
            runSearch();
        }
    });
}

async function runSearch() {
    const q = $('search-input').value.trim();
    if (!q) {
        if (state.searchMode) {
            state.searchMode = false;
            await listFolder(state.currentFolder);
        }
        return;
    }
    if (!state.vaultOpen) return;
    const seq = ++_searchSeq;
    try {
        const hits = await invoke('search_files', { query: q, limit: 200 });
        if (seq !== _searchSeq) return; // 已有更新的查询发出，丢弃过期结果
        state.searchMode = true;
        renderSearchResults(hits);
    } catch (e) {
        if (seq === _searchSeq) showError(String(e));
    }
}

function renderSearchResults(hits) {
    const list = $('file-list');
    list.innerHTML = '';
    state.selectedItems = [];
    if (!hits || !hits.length) {
        list.innerHTML = '<div class="empty-hint"><span>无匹配结果</span></div>';
        setStatus('搜索：无匹配结果');
        return;
    }
    // 2.8.1：与 renderList 相同的 fragment + 委托模式（交互由 bindListDelegation 统一处理）
    const frag = document.createDocumentFragment();
    for (const f of hits) {
        const isFolder = !!f.is_dir;
        const div = document.createElement('div');
        div.className = 'file-item';
        div.dataset.vpath = f.vpath;
        div.dataset.type = isFolder ? 'folder' : 'file';
        div.dataset.name = f.name;
        const fallbackEmoji = isFolder ? '📁' : getIcon(f.name, false);
        // 搜索结果两行展示：名称 + 完整 vpath
        div.innerHTML = `<span class="fi-icon"></span>` +
            `<span class="fi-main"><span class="fi-name">${escapeHtml(f.name)}</span><span class="fi-path">${escapeHtml(f.vpath)}</span></span>` +
            `<span class="fi-size">${isFolder ? '-' : formatSize(f.size)}</span>`;
        const iconSpan = div.querySelector('.fi-icon');
        if (isFolder) iconSpan.textContent = fallbackEmoji;
        else applySysIcon(iconSpan, f.name, fallbackEmoji);
        frag.appendChild(div);
    }
    list.appendChild(frag);
    setStatus(`搜索：${hits.length} 个匹配（双击进入目录 / 打开文件）`);
}

// ───────────────── 2.8.0：移动到其他文件夹 ─────────────────
async function moveSelected() {
    if (!state.selectedItems.length) return;
    const count = state.selectedItems.length;
    let folders = [];
    try {
        folders = await invoke('list_all_folders');
    } catch (e) {
        showError(String(e));
        return;
    }
    const options = ['<option value="/">/（根目录）</option>']
        .concat((folders || []).map(f => `<option value="${escapeAttr(f)}">${escapeHtml(f)}</option>`))
        .join('');
    showDialog('移动到…',
        `<label>目标文件夹（${count} 项）：</label><select id="dlg-move-select">${options}</select>` +
        `<div id="dlg-move-preview" style="color:#657589;font-size:12px;margin-top:2px;"></div>`,
        [
            { text: '移动', cls: 'btn-ok', action: async () => {
                const dest = $('dlg-move-select').value;
                const vpaths = state.selectedItems.map(i => i.vpath);
                try {
                    const raw = await invoke('move_items', { vpaths, destFolder: dest });
                    const res = typeof raw === 'string' ? JSON.parse(raw) : raw;
                    await listFolder(state.currentFolder);
                    setStatus(res.fail > 0
                        ? `移动完成: 成功 ${res.ok} 个，失败 ${res.fail} 个`
                        : `已移动 ${res.ok} 个项目 → ${dest}`);
                    if (res.fail > 0 && res.errors && res.errors.length) showError(res.errors.join('\n'));
                    return true;
                } catch (e) {
                    showError(String(e));
                    return false;
                }
            }},
            { text: '取消', cls: 'btn-cancel' },
        ]
    );
    const sel = $('dlg-move-select');
    const preview = $('dlg-move-preview');
    const updatePreview = () => {
        const dest = sel.value;
        const names = state.selectedItems.map(i => dest === '/' ? '/' + i.name : dest + '/' + i.name);
        preview.textContent = '→ ' + names.join('，');
    };
    sel.onchange = updatePreview;
    updatePreview();
}

// ───────────────── 2.8.0：操作记录（审计日志查看器） ─────────────────
async function showAuditLog() {
    try {
        const raw = await invoke('get_audit_log', { limit: 500 });
        const entries = typeof raw === 'string' ? JSON.parse(raw) : raw;
        let body;
        if (!entries || !entries.length) {
            body = '<p class="audit-note">暂无记录</p>';
        } else {
            const rows = entries.map(e => {
                const d = new Date((e.ts || 0) * 1000);
                return `<div class="audit-row"><span class="audit-ts">${escapeHtml(d.toLocaleString('zh-CN'))}</span><span class="audit-event">${escapeHtml(e.event)}</span></div>`;
            }).join('');
            body = `<div class="audit-list">${rows}</div>`;
        }
        showDialog('操作记录（最近 500 条，最新在前）',
            body + '<p class="audit-note">记录由链式 HMAC 保护：任何篡改都会被检测并截断。</p>',
            [{ text: '关闭', cls: 'btn-ok' }], true);
    } catch (e) {
        showError(String(e));
    }
}

// ───────────────── 2.8.0：全库完整性体检 ─────────────────
async function verifyIntegrity() {
    showDialog('完整性体检',
        '<div class="verify-box"><div id="verify-status">正在逐文件校验认证标签…（大保险柜需要一些时间）</div>' +
        '<div class="progress-track"><div id="verify-bar" class="progress-fill" style="width:0%"></div></div></div>' +
        '<p class="audit-note">体检为只读操作，期间其他保险柜操作将排队等待扫描完成。</p>',
        [{ text: '关闭', cls: 'btn-cancel', action: () => true }]);
    try {
        const raw = await invoke('verify_vault_integrity');
        const res = typeof raw === 'string' ? JSON.parse(raw) : raw;
        const box = document.querySelector('#dialog-body .verify-box');
        if (!box) return; // 对话框已被用户关闭
        if (!res.broken || !res.broken.length) {
            box.innerHTML = `<div class="verify-ok">✓ 全部 ${res.total} 个文件校验通过，未发现损坏</div>`;
        } else {
            const rows = res.broken.map(b =>
                `<div class="audit-row"><span class="audit-event">${escapeHtml(b.vpath)}</span><span class="audit-ts">${escapeHtml(b.reason)}</span></div>`
            ).join('');
            box.innerHTML = `<div class="verify-bad">✗ 发现 ${res.broken.length} / ${res.total} 个文件异常：</div><div class="audit-list">${rows}</div>` +
                '<p class="audit-note">异常文件可能已损坏（位腐 / 云同步冲突），建议从外部备份重新导入。请勿删除保险柜文件。</p>';
        }
    } catch (e) {
        const box = document.querySelector('#dialog-body .verify-box');
        if (box) box.innerHTML = `<div class="verify-bad">体检失败：${escapeHtml(String(e))}</div>`;
    }
}

// ───────────────── 2.8.0：修改保险柜密码 ─────────────────
async function changePassword() {
    showDialog('修改保险柜密码',
        `<label>当前密码：</label><input type="password" id="cp-current">` +
        `<label>新密码（至少 12 位）：</label><input type="password" id="cp-new">` +
        `<label>确认新密码：</label><input type="password" id="cp-new2">` +
        `<div id="cp-error" style="color:#ff6666;font-size:12px;min-height:14px;"></div>` +
        `<p class="audit-note">新格式（v5）保险柜仅重写头部，瞬间完成；旧格式（v4）保险柜将自动升级并全库重加密（需要一些时间）。升级后旧版本 LynVault 将无法打开该保险柜。</p>`,
        [
            { text: '修改', cls: 'btn-ok', action: async () => {
                const cur = $('cp-current').value;
                const np = $('cp-new').value;
                const np2 = $('cp-new2').value;
                const err = $('cp-error');
                if (!cur || !np) { err.textContent = '请填写完整'; return false; }
                if (np !== np2) { err.textContent = '两次输入的新密码不一致'; return false; }
                if ([...np].length < 12) { err.textContent = '新密码长度至少 12 位（按字符计）'; return false; }
                try {
                    setStatus('正在修改密码…（v4 老保险柜会自动升级并重加密，可能耗时较长）');
                    await invoke('change_password', { currentPassword: cur, newPassword: np, keyFilePath: null });
                    setStatus('密码修改成功');
                    return true;
                } catch (e) {
                    err.textContent = String(e);
                    return false;
                }
            }},
            { text: '取消', cls: 'btn-cancel' },
        ]
    );
    setTimeout(() => { const el = $('cp-current'); if (el) el.focus(); }, 50);
}

// ───────────────── 2.8.0：设置（持久化 + 主题 / 自动锁定 / 窗口尺寸） ─────────────────
async function openSettings() {
    let data;
    try {
        data = await invoke('get_settings');
    } catch (e) {
        showError(String(e));
        return;
    }
    if (!data.enabled) {
        // 未启用持久化：按设计只显示「启动持久化」入口
        showDialog('设置',
            '<div class="settings-persist-hint">当前未启用设置持久化 —— 主题、窗口尺寸、自动锁定时长不会保存。<br>启用后配置写入你选择的位置（U 盘便携 / 固定安装二选一）。</div>' +
            '<button id="btn-enable-persist" class="persist-btn">启动持久化</button>',
            [{ text: '关闭', cls: 'btn-cancel' }]
        );
        $('btn-enable-persist').onclick = () => showEnablePersistence();
        return;
    }
    const s = data.settings;
    const themeSwatches = KNOWN_THEMES.map(t =>
        `<label class="theme-swatch" title="${t}"><input type="radio" name="cfg-theme" value="${t}" ${s.theme === t ? 'checked' : ''}><span class="swatch swatch-${t}"></span></label>`
    ).join('');
    showDialog('设置',
        `<div class="settings-path">配置文件：${escapeHtml(data.path)}</div>` +
        `<div class="settings-row"><label>主题：</label><div class="theme-swatches">${themeSwatches}</div></div>` +
        `<div class="settings-row"><label>自动锁定（分钟，0=禁用）：</label><input type="text" id="cfg-autolock" value="${s.autolock_minutes}"></div>` +
        `<div class="settings-row"><label>窗口尺寸：</label><span class="win-size"><input type="text" id="cfg-w" value="${Math.round(s.window_width)}"> × <input type="text" id="cfg-h" value="${Math.round(s.window_height)}"></span></div>` +
        `<div class="settings-row"><label>防截屏保护：</label><input type="checkbox" id="cfg-anti" ${s.anti_screenshot ? 'checked' : ''}></div>` +
        `<div id="cfg-error" style="color:#ff6666;font-size:12px;min-height:14px;"></div>` +
        '<p class="audit-note">防截屏：开启后本窗口不会出现在截屏 / 录屏 / 远程共享画面中（Win10 2004+ 完全隐藏，旧系统显示为黑块；无法阻止物理拍摄）。</p>',
        [
            { text: '保存', cls: 'btn-ok', action: async () => {
                const err = $('cfg-error');
                const w = parseFloat($('cfg-w').value);
                const h = parseFloat($('cfg-h').value);
                const mins = parseInt($('cfg-autolock').value, 10);
                if (!Number.isFinite(w) || w < 480 || w > 3840 || !Number.isFinite(h) || h < 360 || h > 2160) {
                    err.textContent = '窗口尺寸无效（允许 480-3840 × 360-2160）';
                    return false;
                }
                if (!Number.isFinite(mins) || mins < 0 || mins > 240) {
                    err.textContent = '自动锁定时长无效（0-240 分钟）';
                    return false;
                }
                const checked = document.querySelector('input[name="cfg-theme"]:checked');
                const newSettings = {
                    theme: checked ? checked.value : 'blue',
                    autolock_minutes: mins,
                    window_width: w,
                    window_height: h,
                    anti_screenshot: $('cfg-anti').checked,
                };
                try {
                    await invoke('save_settings', { settings: newSettings });
                    settingsEnabled = true;
                    appSettings = newSettings;
                    applyTheme(newSettings.theme);
                    applyWindowSize(newSettings.window_width, newSettings.window_height);
                    resetIdleTimer();
                    setStatus('设置已保存');
                    return true;
                } catch (e) {
                    err.textContent = String(e);
                    return false;
                }
            }},
            { text: '关闭持久化', cls: 'btn-cancel', action: async () => {
                const ok = await tauriAsk('关闭并删除配置文件？所有设置将恢复默认。', { title: '确认', type: 'warning' });
                if (!ok) return false;
                try {
                    await invoke('disable_persistence');
                    settingsEnabled = false;
                    setStatus('已关闭持久化');
                    setTimeout(() => openSettings(), 50); // 关闭后回到「未启用」视图
                    return true;
                } catch (e) {
                    showError(String(e));
                    return false;
                }
            }},
            { text: '取消', cls: 'btn-cancel' },
        ]
    );
}

function showEnablePersistence() {
    showDialog('启动持久化',
        '<p style="margin-bottom:6px;">选择配置文件存放位置：</p>' +
        '<label class="persist-option"><input type="radio" name="persist-loc" value="portable" checked>' +
        '<span><b>当前路径</b>（程序所在目录，配置随程序移动 —— 适配 U 盘 / 便携使用）</span></label>' +
        '<label class="persist-option"><input type="radio" name="persist-loc" value="appdata">' +
        '<span><b>用户文件夹</b>（%APPDATA%\\LynVault —— 适配固定安装 / 程序目录只读时）</span></label>' +
        '<div id="persist-error" style="color:#ff6666;font-size:12px;min-height:14px;"></div>',
        [
            { text: '启动', cls: 'btn-ok', action: async () => {
                const checked = document.querySelector('input[name="persist-loc"]:checked');
                try {
                    const path = await invoke('enable_persistence', { location: checked ? checked.value : 'portable' });
                    settingsEnabled = true;
                    setStatus('已启用持久化：' + path);
                    setTimeout(() => openSettings(), 50); // 回到完整设置界面
                    return true;
                } catch (e) {
                    $('persist-error').textContent = String(e);
                    return false;
                }
            }},
            { text: '取消', cls: 'btn-cancel' },
        ]
    );
}

// ───────────────── 2.8.0：空闲自动锁定（默认 2 分钟） ─────────────────
const IDLE_DEFAULT_MINUTES = 2;
let _idleTimer = null;
let _lastActivity = 0;

function idleMinutes() {
    const m = Number(appSettings && appSettings.autolock_minutes);
    return Number.isFinite(m) && m >= 0 ? m : IDLE_DEFAULT_MINUTES;
}

function resetIdleTimer() {
    if (_idleTimer) { clearTimeout(_idleTimer); _idleTimer = null; }
    const mins = idleMinutes();
    if (!state.vaultOpen || mins <= 0) return;
    _idleTimer = setTimeout(autoLockVault, mins * 60 * 1000);
}

function noteActivity() {
    // mousemove 高频触发：仅每 5 秒真正重置一次计时器
    const now = Date.now();
    if (_idleTimer && now - _lastActivity < 5000) return;
    _lastActivity = now;
    resetIdleTimer();
}

// 空闲触发：先自动保存未保存的编辑（用户要求），再关闭并回到启动弹窗
async function autoLockVault() {
    if (!state.vaultOpen) return;
    _idleTimer = null;
    // 2.8.1：触发前复查最近 30 秒内是否有过活动（noteActivity 的 5 秒节流
    // 存在理论上漏记的可能）—— 有则顺延计时而不是关柜
    if (Date.now() - _lastActivity < 30000) {
        resetIdleTimer();
        return;
    }
    let savedNote = '';
    try {
        const ta = document.querySelector('#dialog-body textarea.txt-editor');
        if (ta && !ta.readOnly && ta.dataset.vpath && ta.value !== ta.dataset.original) {
            const enc = new TextEncoder().encode(ta.value);
            let binStr = '';
            const CHUNK = 0x8000;
            for (let i = 0; i < enc.length; i += CHUNK) {
                binStr += String.fromCharCode.apply(null, enc.subarray(i, i + CHUNK));
            }
            await invoke('update_file_content', { vpath: ta.dataset.vpath, contentB64: btoa(binStr) });
            savedNote = '（编辑内容已自动保存）';
        }
    } catch (e) {
        savedNote = '（警告：编辑内容自动保存失败）';
    }
    try {
        await invoke('close_vault');
        toggleUI(false);
        hideDialog();
        hideCtxMenu();
        setStatus(`空闲超时，保险柜已自动锁定${savedNote}`);
        // 回到启动弹窗（快速重新打开）
        detectAndShowStartup();
    } catch (e) {
        showError(String(e));
    }
}

// ───────────────── 窗口控制 ─────────────────
function bindWindowControls() {
    const tauriWindow = window.__TAURI__ && window.__TAURI__.window;
    if (!tauriWindow) return;
    const appWindow = tauriWindow.getCurrent();

    $('btn-minimize').onclick = () => appWindow.minimize();
    $('btn-window-close').onclick = () => appWindow.close();
    $('btn-maximize').onclick = async () => {
        try {
            if (await appWindow.isMaximized()) await appWindow.unmaximize();
            else await appWindow.maximize();
        } catch (e) { console.warn('[LynVault] Window maximize failed:', e); }
    };
}

// ───────────────── 事件绑定 ─────────────────
function bindEvents() {
    bindWindowControls();
    // 2.4.1：标题栏右侧开源仓库链接 —— 调系统默认浏览器打开。
    // 优先走 __TAURI__.shell.open（需 tauri.conf.json 开 shell.open 白名单），
    // 旧注入不可用时退回 plugin:shell|open 命令；两者都失败则不拦截 <a> 默认行为。
    const repoLink = $('repo-link');
    if (repoLink) {
        repoLink.onclick = async (e) => {
            const url = repoLink.href;
            try {
                if (window.__TAURI__ && window.__TAURI__.shell && window.__TAURI__.shell.open) {
                    e.preventDefault();
                    await window.__TAURI__.shell.open(url);
                } else {
                    e.preventDefault();
                    await invoke('plugin:shell|open', { url });
                }
            } catch (err) {
                console.warn('打开外部链接失败（保留默认行为）:', err);
            }
        };
    }
    $('btn-create').onclick = createVault;
    $('btn-open').onclick = openVault;
    $('btn-close').onclick = closeVault;
    $('btn-import-file').onclick = importFiles;
    $('btn-import-folder').onclick = importFolder;
    $('btn-newfolder').onclick = newFolder;
    $('btn-extract-all').onclick = extractAllFiles;
    $('btn-defrag').onclick = defragmentVault;
    $('btn-destroy').onclick = destroyVault;
    $('btn-add-part').onclick = addPartition;
    $('btn-del-part').onclick = removePartition;
    // 2.8.0：改密码 / 操作记录 / 完整性体检 / 设置
    $('btn-change-pwd').onclick = changePassword;
    $('btn-audit').onclick = showAuditLog;
    $('btn-verify').onclick = verifyIntegrity;
    $('btn-settings').onclick = openSettings;
    // 2.8.0：搜索框
    bindSearch();
    // 2.8.1：列表事件委托（配合 fragment 渲染）
    bindListDelegation();
    // 2.8.0：空闲自动锁定的活动监听（mousemove 高频，noteActivity 内部节流）
    ['pointerdown', 'keydown', 'wheel', 'mousemove', 'touchstart'].forEach(evt => {
        document.addEventListener(evt, noteActivity, { passive: true });
    });

    // 导航
    $('btn-up').onclick = () => {
        const cur = state.currentFolder;
        if (cur === '/') return;
        const parent = cur.substring(0, cur.lastIndexOf('/')) || '/';
        listFolder(parent);
    };
    $('path-input').onkeydown = e => {
        if (e.key === 'Enter') {
            const v = e.target.value.trim();
            if (v) listFolder(v);
        }
    };

    // 右键菜单（2.3.0：委托分发，内容由 showItemMenu/showBlankMenu 动态构建）
    $('ctx-menu').onclick = async (e) => {
        const el = e.target.closest('[data-act]');
        if (!el) return;
        const act = el.dataset.act;
        const menu = $('ctx-menu');
        const item = menu._item;
        hideCtxMenu();
        switch (act) {
            case 'open':
                if (!item) break;
                if (item.type === 'folder') navigateTo(item.vpath);
                else viewFile(item.vpath, item.name);
                break;
            case 'extract':
                // 多选时作用于全部选中项（右键时若该条目已在多选中则保留整组选择）
                await extractSelected();
                break;
            case 'move':
                // 2.8.0：移动到柜内其他文件夹（多选支持）
                await moveSelected();
                break;
            case 'rename':
                if (!item) break;
                state.selectedItems = [item]; // 重命名为单项操作
                await renameSelected();
                break;
            case 'delete':
                // 多选时作用于全部选中项
                await deleteSelected();
                break;
            case 'new-folder':
                await newFolder();
                break;
            case 'import-file':
                await importFiles();
                break;
            case 'import-folder':
                await importFolder();
                break;
            case 'select-all':
                selectAllItems();
                break;
        }
    };

    // 空白区右键：全选 / 新建文件夹 / 导入（仅保险柜打开时）
    $('file-list').addEventListener('contextmenu', (e) => {
        if (!state.vaultOpen) return;
        if (e.target.closest('.file-item')) return; // 条目右键已由条目自身处理
        e.preventDefault();
        showBlankMenu(e.clientX, e.clientY);
    });

    // 2.3.0 新增：Ctrl+A 全选当前目录（输入框内保持原生全选文本行为）
    document.addEventListener('keydown', (e) => {
        if (!state.vaultOpen) return;
        if (!(e.ctrlKey || e.metaKey) || e.key.toLowerCase() !== 'a') return;
        const tag = e.target && e.target.tagName;
        if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;
        e.preventDefault();
        selectAllItems();
    });

    // 全局点击关闭右键菜单
    document.addEventListener('click', hideCtxMenu);
    $('overlay').onclick = hideDialog;

    // ────────── 拖放导入 ──────────
    const fileList = $('file-list');

    // HTML5 dragover 让 drop 光标出现（必须 preventDefault）
    fileList.addEventListener('dragover', (e) => {
        if (!state.vaultOpen) return;
        e.preventDefault();
        fileList.classList.add('drag-over');
    });
    fileList.addEventListener('dragleave', () => {
        fileList.classList.remove('drag-over');
    });

    // 用 Tauri Window API 捕获 dropped 文件路径（比 event.listen 更可靠）
    if (window.__TAURI__ && window.__TAURI__.window) {
        const appWindow = window.__TAURI__.window.getCurrent();
        appWindow.onFileDropEvent(async (evt) => {
            const p = evt.payload;
            try {
                if (p.type === 'hover') {
                    if (state.vaultOpen) fileList.classList.add('drag-over');
                } else if (p.type === 'drop') {
                    fileList.classList.remove('drag-over');
                    const paths = p.paths;
                    if (!paths || paths.length === 0) return;

                    // ── 2.4.1 新功能：拖入 .lyt 保险柜文件自动识别 ──
                    // 保险柜文件不是待加密数据：识别成功直接进入「打开保险柜」
                    // 密码流程，而不是把它导入当前保险柜。
                    if (!state.vaultOpen) {
                        const candidates = paths.filter(x => /\.(lyt|vault)$/i.test(String(x)));
                        if (candidates.length > 0) {
                            // 后端双重校验（扩展名 + magic bytes），避免误识别
                            const checks = await Promise.all(candidates.map(x =>
                                invoke('check_vault_file', { path: x }).catch(() => false)
                            ));
                            const confirmed = candidates.filter((x, i) => checks[i] === true);
                            if (confirmed.length > 0) {
                                const skipped = paths.length - confirmed.length;
                                if (skipped > 0) setStatus(`已识别保险柜文件；另有 ${skipped} 个项目未导入（请打开后再拖入）`);
                                openVaultFromExternal(confirmed[0]);
                                return;
                            }
                        }
                        return; // 保险柜未打开且拖入的不是保险柜文件：忽略
                    }

                    setStatus(`正在导入 ${paths.length} 个项目...`);
                    const raw = await invoke('import_dropped_paths', {
                        paths,
                        destBase: state.currentFolder,
                    });
                    const res = typeof raw === 'string' ? JSON.parse(raw) : raw;
                    await listFolder(state.currentFolder);

                    // 2.4.1：后端会把误拖入的保险柜文件分流出来（不导入）
                    let summary = res.summary || '拖放导入完成';
                    if (res.vault_files && res.vault_files.length > 0) {
                        summary += `\n已跳过 ${res.vault_files.length} 个保险柜文件（不能嵌套导入，请先关闭当前保险柜再打开它）`;
                    }
                    setStatus(summary);
                } else {
                    // cancel / leave
                    fileList.classList.remove('drag-over');
                }
            } catch (e) {
                fileList.classList.remove('drag-over');
                setStatus('拖放导入失败');
                showError(String(e));
                await listFolder(state.currentFolder);
            }
        });
    }
}

// ───────────────── 启动检测弹窗 ─────────────────
// 弹窗不可关闭，背景窗口变灰。仅在选择打开/新建后才会隐藏。

// N13 修复：过滤器配置提取为常量，避免重复
const VAULT_FILTERS = [
    { name: 'LynVault', extensions: ['lyt'] },
    { name: 'LynVault (旧版)', extensions: ['vault'] },
];
const VAULT_OPEN_FILTERS = [
    { name: 'LynVault', extensions: ['lyt', 'vault'] },
];

// N10 修复：列表项防重入标志，防止快速双击弹出多个密码框
let _startupProcessing = false;

function showStartupModal() {
    document.body.classList.add('has-modal');
    $('overlay').classList.add('startup-modal');
    $('overlay').classList.remove('hidden');
    $('startup-dialog').classList.remove('hidden');
    // N9 修复：启动弹窗显示时，遮罩不绑定 hideDialog（保持不可关闭）
    $('overlay').onclick = null;
    _startupProcessing = false;
}

function hideStartupModal() {
    document.body.classList.remove('has-modal');
    $('overlay').classList.remove('startup-modal');
    $('overlay').classList.add('hidden');
    $('startup-dialog').classList.add('hidden');
    // 恢复 overlay 的正常行为
    $('overlay').onclick = hideDialog;
}

function renderStartupList(items) {
    const list = $('startup-list');
    list.innerHTML = '';
    if (!items || items.length === 0) {
        list.innerHTML = '<div class="sd-empty">当前目录下未发现保险柜文件<br>请选择「新建保险柜」或「打开其他保险柜」</div>';
        return;
    }
    for (const it of items) {
        const div = document.createElement('div');
        div.className = 'sd-item';
        const d = new Date((it.mtime || 0) * 1000);
        const ts = d.toLocaleString('zh-CN');
        const sizeStr = formatSize(it.size || 0);
        // 转义防止 XSS
        const safeName = escapeHtml(it.name);
        const safePath = escapeAttr(it.path);
        div.innerHTML = `<span class="sd-icon">🔒</span>` +
            `<div class="sd-info">` +
            `<div class="sd-name" title="${safePath}">${safeName}</div>` +
            `<div class="sd-meta">${ts} · ${sizeStr}</div>` +
            `</div>`;
        div.onclick = () => {
            // N10 修复：防重入，处理中时忽略后续点击
            if (_startupProcessing) return;
            _startupProcessing = true;
            openVaultFromStartup(it.path);
        };
        list.appendChild(div);
    }
}

// R1+R2 修复：取消时通过 onCancel 重置 _startupProcessing；
// 密码错误时用 showInlineInputError 不销毁密码框，让用户重试
// Q2 修复：onCancel 时若启动弹窗已隐藏（来自 sd-open-other 流程），重新显示
function openVaultFromStartup(filePath) {
    if (!filePath) { _startupProcessing = false; return; }
    showInput('打开保险柜', '输入主密码：', '', async (pwd) => {
        if (!pwd) {
            // 空密码点确定，等同于取消
            _startupProcessing = false;
            // Q2：若启动弹窗已隐藏（来自 sd-open-other），重新显示
            if ($('startup-dialog').classList.contains('hidden')) {
                showStartupModal();
            }
            return true;
        }
    try {
        await invoke('open_vault', { path: filePath, password: pwd, keyFilePath: null });
        hideStartupModal();
        toggleUI(true);
        await listFolder('/');
        setStatus('保险柜已打开');
        _startupProcessing = false;
        return true; // 成功，关闭密码框
    } catch (e) {
        // R2 修复：内联显示错误，不销毁密码框
        showInlineInputError(String(e));
        return false; // 保留密码框让用户重试
    }
}, true, () => {
    // R1 修复：取消按钮回调，重置状态
    _startupProcessing = false;
    // Q2 修复：若启动弹窗已隐藏（来自 sd-open-other 流程），重新显示
    if ($('startup-dialog').classList.contains('hidden')) {
        showStartupModal();
    }
});
    // 2.8.0：开锁前展示该保险柜的历史失败尝试次数
    fetchLockHint(filePath);
}

// ───────────────── 2.4.1：外部来源打开保险柜 ─────────────────
// 统一处理三种来源：双击 .lyt 启动参数、已运行实例转发的请求、拖放到窗口。
// 已有保险柜打开时提示先关闭；取消时回到启动检测弹窗。
function openVaultFromExternal(filePath) {
    if (!filePath) return;
    if (state.vaultOpen) {
        showDialog('提示',
            '<p>已打开一个保险柜。</p><p>请先关闭当前保险柜，再打开新的保险柜文件。</p>',
            [{ text: '确定', cls: 'btn-ok' }]);
        return;
    }
    if (_startupProcessing) return; // 防重入
    _startupProcessing = true;
    // 2.7.1 安全修复：先把完整目标路径显示给用户确认，拒绝即不采集口令 ——
    // 单实例端口接受任意本地进程连接，路径由对端指定；不确认就让用户输入口令，
    // 恶意进程可用候选口令预建 .lyt 来验证用户口令（口令验证预言机）。
    tauriAsk(
        `收到打开保险柜的请求：\n${filePath}\n\n是否打开该保险柜？\n若非您本人的操作，请选择「否」。`,
        { title: '打开保险柜请求', type: 'warning' }
    ).then(ok => {
        if (!ok) {
            _startupProcessing = false;
            // 拒绝：回到启动检测弹窗（若此前已隐藏）
            if ($('startup-dialog').classList.contains('hidden')) {
                showStartupModal();
            }
            return;
        }
        hideStartupModal();
        openVaultFromStartup(filePath);
    });
}

// 2.4.1：silent 参数 —— 只填充列表不弹窗。用于「双击 .lyt 启动」场景的
// 后台预扫描：用户取消密码输入回到启动弹窗时，列表已有内容。
async function detectAndShowStartup(silent) {
    // 并行扫描多个候选目录（桌面、文档、下载、主目录）
    const candidates = ['$DESKTOP', '$DOCUMENT', '$DOWNLOAD', '$HOME'];
    const results = await Promise.all(candidates.map(c =>
        invoke('scan_vault_files', { dir: c }).catch(() => [])
    ));
    // 合并 + 去重（按 path）
    const seen = new Set();
    const found = results.flat().filter(it => {
        if (!it || !it.path || seen.has(it.path)) return false;
        seen.add(it.path);
        return true;
    });
    // 按修改时间倒序
    found.sort((a, b) => (b.mtime || 0) - (a.mtime || 0));

    renderStartupList(found);
    if (!silent) showStartupModal();
}

// ───────────────── 启动 ─────────────────
// 2.4.1 修复：回调必须为 async —— 内部有 await（事件注册 / 启动参数查询）。
// 旧写法在非 async 回调里用 await 是语法错误，整个 app.js 解析失败，
// 表现为：按钮全部点不动、启动扫描不运行。
window.addEventListener('DOMContentLoaded', async () => {
    if (!initTauri()) {
        document.body.innerHTML = '<div style="padding:40px;color:#ff6666">Tauri API 不可用，请确保从 Tauri 启动应用。</div>';
        return;
    }
    // 2.8.0：先加载设置持久化（主题 / 自动锁定时长），再决定窗口尺寸策略
    await loadSettings();
    // 2.3.0 修复：窗口由「屏幕短边 75% 正方形」改为横屏 3:2 比例，
    // 并整体按比例缩小（宽度 ≤ 屏幕 60%，上限 1024；高度 ≤ 屏幕 80%），
    // 避免在常见 16:9 屏幕上窗口过高过大。
    // 2.8.0：已启用设置持久化时跳过 —— 后端启动时已按配置尺寸创建窗口
    if (!settingsEnabled) {
        try {
            const w = window.__TAURI__ && window.__TAURI__.window;
            if (w) {
                const appWin = w.getCurrent();
                const LogicalSize = w.LogicalSize;
                const sw = window.screen.width;
                const sh = window.screen.height;
                let width = Math.floor(Math.min(sw * 0.6, 1024));
                let height = Math.floor(Math.min(width * 0.66, sh * 0.8));
                if (height < Math.floor(width * 0.66)) {
                    width = Math.floor(height * 1.5); // 高度受限时按 3:2 反推宽度
                }
                if (LogicalSize) {
                    appWin.setSize(new LogicalSize(width, height));
                } else {
                    appWin.setSize({ width, height });
                }
                appWin.center();
            }
        } catch (e) { /* 非致命：尺寸调整失败不影响功能 */ }
    }
    bindEvents();
    toggleUI(false);
    // N7 修复：扫描期间禁用新建/打开按钮，防止用户在启动弹窗弹出前操作
    $('btn-create').disabled = true;
    $('btn-open').disabled = true;

    // 启动弹窗按钮事件
    $('sd-create').onclick = async () => {
        if (_startupProcessing) return;
        _startupProcessing = true;
        hideStartupModal();
        const filePath = await tauriSave({
            title: '选择保险柜保存位置',
            filters: VAULT_FILTERS,
        });
        if (!filePath) {
            // 用户取消文件选择，重新显示启动弹窗
            _startupProcessing = false;
            showStartupModal();
            return;
        }
        // 进入密码输入流程
        showInput('创建保险柜', '输入主密码：', '', async (pwd) => {
            if (!pwd) {
                _startupProcessing = false;
                showStartupModal();
                return true; // 空密码等同于取消，回到启动弹窗
            }
            try {
                await invoke('create_vault', { path: filePath, password: pwd, keyFilePath: null });
                hideStartupModal();
                toggleUI(true);
                await listFolder('/');
                setStatus('保险柜已创建');
                _startupProcessing = false;
                return true;
            } catch (e) {
                // R2 修复：内联错误，不销毁密码框
                showInlineInputError(String(e));
                return false; // 保留密码框重试
            }
        }, true, () => {
            // R1 修复：取消按钮，回到启动弹窗
            _startupProcessing = false;
            showStartupModal();
        });
    };
    $('sd-open-other').onclick = async () => {
        if (_startupProcessing) return;
        _startupProcessing = true;
        hideStartupModal();
        const filePath = await tauriOpen({
            title: '选择保险柜文件',
            filters: VAULT_OPEN_FILTERS,
        });
        if (!filePath) {
            _startupProcessing = false;
            showStartupModal();
            return;
        }
        // 复用 openVaultFromStartup（已处理取消/错误重试逻辑）
        openVaultFromStartup(filePath);
    };
    // ── 2.4.1 新功能：.lyt 文件导航到软件后自动识别 ──
    // 顺序很重要：先注册事件监听器、再通知后端就绪、最后查询启动参数，
    // 保证「双击 .lyt 启动」与「运行中双击 .lyt 转发」两条路径都不丢事件。
    try {
        if (window.__TAURI__ && window.__TAURI__.event && window.__TAURI__.event.listen) {
            await window.__TAURI__.event.listen('vault-file-requested', (evt) => {
                // 已运行实例收到第二个实例双击的 .lyt 文件
                openVaultFromExternal(evt.payload);
            });
            // 2.8.0：系统锁屏 / 睡眠 / 注销 → 后端已关闭保险柜，前端回启动弹窗。
            // 2.8.1：仅 vaultOpen 时处理 —— 后端已改为只在实际关闭了保险柜时发射；
            // 未开柜时忽略，避免把正在输入的密码框 / 设置对话框无理由关掉
            await window.__TAURI__.event.listen('vault-locked', () => {
                if (!state.vaultOpen) return;
                toggleUI(false);
                hideDialog();
                hideCtxMenu();
                setStatus('系统已锁定 / 睡眠，保险柜已自动关闭');
                detectAndShowStartup();
            });
            // 2.8.0：完整性体检进度（verify-bar 元素存在时刷新）
            await window.__TAURI__.event.listen('integrity-progress', (evt) => {
                const p = evt.payload || {};
                const bar = $('verify-bar');
                const st = $('verify-status');
                if (bar && p.total) bar.style.width = Math.floor((p.done / p.total) * 100) + '%';
                if (st) st.textContent = `正在校验 ${p.done || 0} / ${p.total || '?'}：${p.current || ''}`;
            });
        }
    } catch (e) { console.warn('事件监听注册失败:', e); }
    invoke('frontend_ready').catch(() => { /* 非致命 */ });

    // 双击 .lyt 文件启动（文件关联）：直接进入该文件的密码输入，跳过启动弹窗
    try {
        const launch = await invoke('get_launch_vault_arg');
        if (launch) {
            console.log('[LynVault] 检测到启动参数中的保险柜文件:', launch);
            openVaultFromExternal(launch);
            // 后台静默预扫描：用户取消密码输入回到启动弹窗时列表已就绪
            detectAndShowStartup(true).catch(() => {});
            console.log('[LynVault] UI ready');
            return;
        }
    } catch (e) { console.warn('读取启动参数失败:', e); }

    // 启动检测：扫描附近目录的 .lyt / .vault 文件
    detectAndShowStartup();
    console.log('[LynVault] UI ready');
});
