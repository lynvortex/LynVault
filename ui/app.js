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
};

// ───────────────── DOM ─────────────────
const $ = id => document.getElementById(id);

// ───────────────── 工具函数 ─────────────────
function toggleUI(open) {
    state.vaultOpen = open;
    const ids = ['btn-close', 'btn-add-part', 'btn-del-part', 'btn-import-file',
        'btn-import-folder', 'btn-extract', 'btn-delete', 'btn-new-folder',
        'btn-view', 'btn-audit', 'btn-defrag', 'btn-destroy'];
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

// ───────────────── 模态框 ─────────────────
function showDialog(title, bodyHtml, buttons, wide) {
    const dlg = $('dialog');
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
            if (b.action) b.action();
            hideDialog();
        };
        btnContainer.appendChild(btn);
    });
    $('overlay').classList.remove('hidden');
    $('dialog').classList.remove('hidden');
}

function hideDialog() {
    const dlg = $('dialog');
    dlg.style.width = '';
    dlg.style.height = '';
    dlg.style.maxWidth = '';
    dlg.style.left = '';
    dlg.style.top = '';
    dlg.style.transform = 'translate(-50%, -50%)';
    $('overlay').classList.add('hidden');
    dlg.classList.add('hidden');
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

function showInput(title, label, defaultValue, callback, isPassword) {
    const type = isPassword ? 'password' : 'text';
    showDialog(title,
        `<label>${label}</label><input type="${type}" id="dlg-input" value="${defaultValue || ''}">`,
        [
            { text: '确定', cls: 'btn-ok', action: () => callback($('dlg-input').value) },
            { text: '取消', cls: 'btn-cancel' }
        ]
    );
    setTimeout(() => { const inp = $('dlg-input'); if (inp) { inp.focus(); inp.select(); } }, 50);
}

function showError(msg) {
    const pre = document.createElement('pre');
    pre.style.color = '#ff6666';
    pre.textContent = msg;
    showDialog('错误', pre.outerHTML, [{ text: '确定', cls: 'btn-ok' }]);
}

// ───────────────── 右键菜单 ─────────────────
function showCtxMenu(x, y, item) {
    const menu = $('ctx-menu');
    menu.classList.remove('hidden');
    menu.style.left = x + 'px';
    menu.style.top = y + 'px';
    menu._item = item;
    // 根据类型调整文案
    const openItem = menu.querySelector('[data-act="open"]');
    openItem.textContent = item.type === 'folder' ? '打开文件夹' : '安全查看';
}

function hideCtxMenu() {
    $('ctx-menu').classList.add('hidden');
}

// ───────────────── 列表渲染 ─────────────────
function renderList(data) {
    const list = $('file-list');
    list.innerHTML = '';
    state.selectedItems = [];

    if (!data || !data.length) {
        list.innerHTML = '<div class="empty-hint">空文件夹 — 使用「导入文件」添加内容</div>';
        return;
    }

    data.forEach(f => {
        const div = document.createElement('div');
        div.className = 'file-item';
        div.dataset.vpath = f.vpath;
        div.dataset.type = f.type;
        div.dataset.name = f.name;
        const isFolder = f.type === 'folder';
        div.innerHTML = `<span class="fi-icon">${isFolder ? '📁' : getIcon(f.name, false)}</span><span class="fi-name">${f.name}</span><span class="fi-size">${isFolder ? '-' : formatSize(f.size)}</span>`;
        div.onclick = e => selectItem(div, e);
        div.ondblclick = () => isFolder ? navigateTo(f.vpath) : viewFile(f.vpath, f.name);
        div.oncontextmenu = e => { e.preventDefault(); selectItem(div, e); showCtxMenu(e.clientX, e.clientY, { vpath: f.vpath, type: f.type, name: f.name }); };
        list.appendChild(div);
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

// ───────────────── 核心操作 ─────────────────
async function listFolder(folder) {
    try {
        const raw = await invoke('list_folder', { folder });
        const data = typeof raw === 'string' ? JSON.parse(raw) : raw;
        state.currentFolder = folder;
        $('path-input').value = folder;
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
    // 选择保存路径
    const filePath = await tauriSave({
        title: '选择保险柜保存位置',
        filters: [{ name: 'LynVault', extensions: ['vault'] }],
    });
    if (!filePath) return;

    showInput('创建保险柜', '输入主密码：', '', async (pwd) => {
        if (!pwd) return;
        try {
            await invoke('create_vault', { path: filePath, password: pwd, keyFilePath: null });
            toggleUI(true);
            await listFolder('/');
            setStatus('保险柜已创建');
        } catch (e) {
            showError(String(e));
        }
    }, true);
}

async function openVault() {
    const filePath = await tauriOpen({
        title: '选择保险柜文件',
        filters: [{ name: 'LynVault', extensions: ['vault'] }],
    });
    if (!filePath) return;

    showInput('打开保险柜', '输入主密码：', '', async (pwd) => {
        if (!pwd) return;
        try {
            await invoke('open_vault', { path: filePath, password: pwd, keyFilePath: null });
            toggleUI(true);
            await listFolder('/');
            setStatus('保险柜已打开');
        } catch (e) {
            showError(String(e));
        }
    }, true);
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
    const count = Array.isArray(files) ? files.length : 1;
    setStatus(`正在导入 ${count} 个文件...`);
    try {
        const fileList = Array.isArray(files) ? files : [files];
        for (const f of fileList) {
            await invoke('import_file', { srcPath: f, destVpath: state.currentFolder });
        }
        await listFolder(state.currentFolder);
        setStatus(`导入完成: ${count} 个文件`);

        // 提示安全删除源文件
        const del = await tauriAsk(`导入完成。是否安全删除源文件？

DoD 5220.22-M 7次擦除，不可恢复。`, { title: '安全删除源文件', type: 'warning' });
        if (del) {
            setStatus('正在安全删除源文件...');
            try {
                const result = await invoke('secure_delete_source_files', { paths: fileList });
                setStatus(result);
            } catch (e) {
                showError('安全删除失败: ' + String(e));
            }
        }
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

        // 提示安全删除源文件夹
        const del = await tauriAsk(`导入完成。是否安全删除源文件夹？

DoD 5220.22-M 7次擦除，不可恢复。

${folder}`, { title: '安全删除源文件夹', type: 'warning' });
        if (del) {
            setStatus('正在安全删除源文件夹...');
            try {
                // 遍历文件夹内所有文件并安全删除
                const result = await invoke('secure_delete_source_folder', { folder });
                setStatus(result);
            } catch (e) {
                showError('安全删除失败: ' + String(e));
            }
        }
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
        await invoke('extract_files', { vpaths, destFolder: dest });
        setStatus('提取完成: ' + dest);
    } catch (e) {
        showError(String(e));
    }
}

async function deleteSelected() {
    if (!state.selectedItems.length) return;
    const names = state.selectedItems.map(i => i.name).join('\n');
    const ok = await tauriAsk(`确认安全删除以下项目？\n\n${names}\n\n此操作不可撤销。`, { title: '确认删除', type: 'warning' });
    if (!ok) return;
    try {
        const vpaths = state.selectedItems.map(i => i.vpath);
        await invoke('delete_files', { vpaths });
        await listFolder(state.currentFolder);
        setStatus('已安全删除');
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

async function viewFile(vpath, fileName) {
    const ext = fileName.split('.').pop().toLowerCase();
    const imgExts = ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'tiff', 'tif'];
    const textExts = ['txt', 'md', 'py', 'log', 'json', 'csv', 'xml', 'ini', 'cfg', 'yaml', 'yml', 'rs', 'js', 'go', 'toml', 'html', 'css', 'sh', 'bat', 'ps1'];
    const officeExts = ['docx', 'doc', 'xlsx', 'xls', 'pptx'];

    try {
        if (officeExts.includes(ext)) {
            const text = await invoke('preview_office_file', { vpath });
            const pre = document.createElement('pre');
            pre.textContent = text;
            showDialog('📄 ' + fileName, pre.outerHTML, [{ text: '关闭', cls: 'btn-ok' }], true);
            return;
        }

        const data = await invoke('load_file_content', { vpath });

        if (imgExts.includes(ext)) {
            const blob = new Blob([new Uint8Array(data)]);
            const url = URL.createObjectURL(blob);
            const zoomId = 'img-zoom-' + Date.now();
            showDialog('🖼️ ' + fileName, `<div style="overflow:auto;max-height:60vh;text-align:center;"><img id="${zoomId}" src="${url}" style="max-width:100%;cursor:zoom-in;transition:transform 0.1s;"></div>`, [{ text: '关闭', cls: 'btn-ok' }], true);
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
            const decoder = new TextDecoder('utf-8');
            const text = decoder.decode(new Uint8Array(data));
            const pre = document.createElement('pre');
            pre.textContent = text;
            showDialog('📄 ' + fileName, pre.outerHTML, [{ text: '关闭', cls: 'btn-ok' }], true);
            return;
        }

        showDialog('提示', `<p>暂不支持预览 .${ext} 格式</p><p>请使用「提取选中」导出后查看。</p>`, [{ text: '确定', cls: 'btn-ok' }]);
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

async function showAudit() {
    try {
        const raw = await invoke('get_audit_log');
        const entries = typeof raw === 'string' ? JSON.parse(raw) : raw;
        if (!entries.length) {
            showDialog('审计日志', '<pre>（暂无记录）</pre>', [{ text: '关闭', cls: 'btn-ok' }]);
            return;
        }
        const lines = entries.map(e => {
            const d = new Date(e.ts * 1000);
            const ts = d.toLocaleString('zh-CN');
            return `[${ts}] ${e.event}`;
        });
        showDialog('审计日志', `<pre>${lines.join('\n')}</pre>`, [{ text: '关闭', cls: 'btn-ok' }]);
    } catch (e) {
        showError(String(e));
    }
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
        const options = partitions.map(p => `<option value="${p.alias}">${p.alias}</option>`).join('');
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

// ───────────────── 事件绑定 ─────────────────
function bindEvents() {
    $('btn-create').onclick = createVault;
    $('btn-open').onclick = openVault;
    $('btn-close').onclick = closeVault;
    $('btn-import-file').onclick = importFiles;
    $('btn-import-folder').onclick = importFolder;
    $('btn-extract').onclick = extractSelected;
    $('btn-delete').onclick = deleteSelected;
    $('btn-new-folder').onclick = newFolder;
    $('btn-view').onclick = () => {
        if (state.selectedItems.length) viewFile(state.selectedItems[0].vpath, state.selectedItems[0].name);
    };
    $('btn-audit').onclick = showAudit;
    $('btn-defrag').onclick = defragmentVault;
    $('btn-destroy').onclick = destroyVault;
    $('btn-add-part').onclick = addPartition;
    $('btn-del-part').onclick = removePartition;

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

    // 右键菜单
    $('ctx-menu').querySelectorAll('[data-act]').forEach(el => {
        el.onclick = async () => {
            const act = el.dataset.act;
            const item = $('ctx-menu')._item;
            hideCtxMenu();
            if (!item) return;
            switch (act) {
                case 'open':
                    if (item.type === 'folder') navigateTo(item.vpath);
                    else viewFile(item.vpath, item.name);
                    break;
                case 'view': viewFile(item.vpath, item.name); break;
                case 'extract':
                    state.selectedItems = [item];
                    await extractSelected();
                    break;
                case 'rename':
                    state.selectedItems = [item];
                    await renameSelected();
                    break;
                case 'delete':
                    state.selectedItems = [item];
                    await deleteSelected();
                    break;
            }
        };
    });

    // 全局点击关闭右键菜单
    document.addEventListener('click', hideCtxMenu);
    $('overlay').onclick = hideDialog;
}

// ───────────────── 启动 ─────────────────
window.addEventListener('DOMContentLoaded', () => {
    if (!initTauri()) {
        document.body.innerHTML = '<div style="padding:40px;color:#ff6666">Tauri API 不可用，请确保从 Tauri 启动应用。</div>';
        return;
    }
    bindEvents();
    toggleUI(false);
    console.log('[LynVault] UI ready');
});
