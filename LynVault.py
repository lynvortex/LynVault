import sys
import os
import json
import struct
import time
from pathlib import Path
from secrets import token_bytes, compare_digest
from typing import Optional, List, Dict, Any, Tuple

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QListView, QToolBar,
    QStatusBar, QFileDialog, QMessageBox, QWidget,
    QVBoxLayout, QHBoxLayout, QMenu, QInputDialog, QLineEdit, QLabel,
    QPushButton, QWidgetAction, QProgressDialog, QStyle,
    QLayout, QToolButton,
)
from PySide6.QtCore import (
    Qt, QAbstractItemModel, QModelIndex, QTimer, Signal,
    QSize, QRect, QPoint,
)
from PySide6.QtGui import (
    QAction, QStandardItemModel, QStandardItem, QDragEnterEvent, QDropEvent,
    QPixmap, QImage, QTransform, QIcon,
)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hmac import HMAC as CryptoHMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# ---------- 参数 ----------
MAGIC = b'PYVAULT4'
VERSION = 4
HEADER_SIZE = 1024
MAX_PARTITIONS = 8
PARTITION_ENTRY_SIZE = 80
MAX_ERRORS = 5
LOCKOUT_SECONDS = 30 * 60
COOLDOWN_SECONDS = 3.0
DEFAULT_PARTITION = "Main"

SHRED_PASSES = 7
PBKDF2_ITERATIONS = 1_000_000
AUDIT_MAX_EVENTS = 10000

LOCK_OFFSET = 887
SIGNED_LENGTH = 887
SIGNATURE_OFFSET = 960
SIGNATURE_SIZE = 64

FMT_HEADER = '<8sB32s32s32s'
FMT_PART   = '<16s32sQQ16s'
FMT_LOCK   = '<Bd'
FMT_LOCK_BLOCK = '<Bd32s'

BACKEND = default_backend()

# ---------- 内存安全 ----------
try:
    import resource
    resource.setrlimit(resource.RLIMIT_MEMLOCK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
except:
    pass

# ---------- 密码学工具 ----------
def derive_keys(password: str, key_file_data: Optional[bytes], salt: bytes) -> Tuple[bytes, bytes, bytes]:
    combined = password.encode('utf-8')
    if key_file_data:
        combined += key_file_data
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=PBKDF2_ITERATIONS, backend=BACKEND
    )
    master = kdf.derive(combined)
    hkdf = HKDF(
        algorithm=hashes.SHA512(), length=96, salt=None,
        info=b'pyvault4-keys', backend=BACKEND
    )
    derived = hkdf.derive(master)
    return derived[:32], derived[32:64], derived[64:96]

def encrypt_gcm(key: bytes, plaintext: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = token_bytes(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct

def decrypt_gcm(key: bytes, data: bytes) -> Optional[bytes]:
    if len(data) < 28:
        return None
    nonce, ct = data[:12], data[12:]
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ct, None)
    except InvalidTag:
        return None

def create_auth_tag(auth_key: bytes) -> bytes:
    h = CryptoHMAC(auth_key, hashes.SHA256(), backend=BACKEND)
    h.update(b'AUTH_OK')
    return h.finalize()

def verify_auth_tag(auth_key: bytes, tag: bytes) -> bool:
    expected = create_auth_tag(auth_key)
    return compare_digest(expected, tag)

def compute_header_signature(payload: bytes, sign_key: bytes) -> bytes:
    h = CryptoHMAC(sign_key, hashes.SHA512(), backend=BACKEND)
    h.update(payload)
    return h.finalize()

def verify_header_signature(header: bytes, sign_key: bytes) -> bool:
    payload = header[:SIGNED_LENGTH]
    stored_sig = header[SIGNATURE_OFFSET:SIGNATURE_OFFSET+SIGNATURE_SIZE]
    expected = compute_header_signature(payload, sign_key)
    return compare_digest(expected, stored_sig)

def compute_lock_hmac(lock_key: bytes, lock_count: int, lock_until: float) -> bytes:
    payload = struct.pack(FMT_LOCK, lock_count & 0xFF, lock_until)
    h = CryptoHMAC(lock_key, hashes.SHA256(), backend=BACKEND)
    h.update(payload)
    return h.finalize()

def verify_lock_hmac(lock_key: bytes, lock_count: int, lock_until: float, stored_hmac: bytes) -> bool:
    expected = compute_lock_hmac(lock_key, lock_count, lock_until)
    return compare_digest(expected, stored_hmac)

# ---------- 安全擦除 (支持进度回调) ----------
def dod_erase(file_path: str, progress_callback=None):
    if not os.path.isfile(file_path):
        return
    length = os.path.getsize(file_path)
    patterns = [b'\x00', b'\xFF']
    total_passes = SHRED_PASSES
    for i in range(total_passes):
        with open(file_path, 'wb') as f:
            for _ in range(length // 1024 + 1):
                f.write(patterns[0] * 1024)
        with open(file_path, 'wb') as f:
            for _ in range(length // 1024 + 1):
                f.write(patterns[1] * 1024)
        with open(file_path, 'wb') as f:
            f.write(token_bytes(length))
        if progress_callback:
            progress_callback(int((i + 1) / total_passes * 100))
    os.remove(file_path)

def validate_vpath(vpath: str) -> bool:
    return vpath.startswith('/') and '..' not in vpath.split('/') and '\\' not in vpath

# ---------- 审计日志 ----------
class AuditLog:
    def __init__(self, auth_key: bytes):
        self.entries = []
        self.auth_key = auth_key
        self.chain = b''

    def add(self, event: str):
        now = time.time()
        prev = self.chain if self.entries else b'\x00'*32
        data = json.dumps({'ts': now, 'event': event}).encode()
        h = CryptoHMAC(self.auth_key, hashes.SHA256(), backend=BACKEND)
        h.update(prev + data)
        self.chain = h.finalize()
        self.entries.append({'ts': now, 'event': event, 'hmac': self.chain.hex()})
        if len(self.entries) > AUDIT_MAX_EVENTS:
            self.entries.pop(0)

    def to_json(self):
        return self.entries

    @classmethod
    def from_json(cls, entries, auth_key):
        log = cls(auth_key)
        log.entries = entries
        if entries:
            log.chain = bytes.fromhex(entries[-1]['hmac'])
        return log

# ---------- VaultFile ----------
class VaultFile:
    def __init__(self, path: str = None):
        self.path = path
        self.handle = None

    def open(self, mode='rb+'):
        if self.path:
            self.handle = open(self.path, mode)

    def close(self):
        if self.handle:
            self.handle.close()
            self.handle = None

    def read_header(self) -> bytes:
        if not self.handle:
            return b''
        self.handle.seek(0)
        return self.handle.read(HEADER_SIZE)

    def write_header(self, data: bytes):
        if self.handle and len(data) == HEADER_SIZE:
            self.handle.seek(0)
            self.handle.write(data)
            self.handle.flush()

    def read_at(self, offset: int, size: int) -> bytes:
        if not self.handle:
            return b''
        self.handle.seek(offset)
        return self.handle.read(size)

    def write_at(self, offset: int, data: bytes):
        if not self.handle:
            return
        self.handle.seek(offset)
        self.handle.write(data)
        self.handle.flush()

    def append(self, data: bytes) -> int:
        if not self.handle:
            return -1
        self.handle.seek(0, 2)
        offs = self.handle.tell()
        self.handle.write(data)
        self.handle.flush()
        return offs

    def size(self) -> int:
        if not self.handle:
            return 0
        self.handle.seek(0, 2)
        return self.handle.tell()

# ---------- VaultCore ----------
class VaultCore:
    def __init__(self):
        self.vault = VaultFile()
        self.salt = token_bytes(32)
        self.lock_key = token_bytes(32)
        self.lock_count = 0
        self.lock_until = 0.0
        self.partitions: List[dict] = []
        self.active_idx = -1
        self.enc_key = None
        self.auth_key = None
        self.sign_key = None
        self.key_file_data = None
        self.audit = None
        self.last_attempt_time = 0.0

    def rename_file(self, old_vpath: str, new_name: str) -> bool:
        if not self.enc_key or not self.vault.handle:
            return False
        parent = old_vpath.rsplit('/', 1)[0] if '/' in old_vpath else '/'
        if parent == '':
            parent = '/'
        new_vpath = (parent.rstrip('/') + '/' + new_name).replace('//', '/')
        if not validate_vpath(new_vpath):
            return False
        idx = self.load_index()
        if old_vpath not in idx['files']:
            return False
        if new_vpath in idx['files'] or new_vpath in idx['folders']:
            return False
        meta = idx['files'].pop(old_vpath)
        meta['name'] = new_name
        idx['files'][new_vpath] = meta
        self.audit.add(f"重命名文件 '{old_vpath}' -> '{new_vpath}'")
        self.save_index(idx)
        return True

    def rename_folder(self, old_vpath: str, new_name: str) -> bool:
        if not self.enc_key or not self.vault.handle:
            return False
        if old_vpath == '/':
            return False
        parent = old_vpath.rsplit('/', 1)[0] if '/' in old_vpath else '/'
        if parent == '':
            parent = '/'
        new_vpath = (parent.rstrip('/') + '/' + new_name).replace('//', '/')
        if not validate_vpath(new_vpath):
            return False
        idx = self.load_index()
        if old_vpath not in idx['folders']:
            return False
        if new_vpath in idx['folders'] or new_vpath in idx['files']:
            return False
        new_files = {}
        new_folders = {}
        old_prefix = old_vpath + '/'
        new_prefix = new_vpath + '/'
        for vpath, meta in idx['files'].items():
            if vpath == old_vpath or vpath.startswith(old_prefix):
                migrated_path = new_vpath if vpath == old_vpath else new_prefix + vpath[len(old_prefix):]
                new_files[migrated_path] = meta
            else:
                new_files[vpath] = meta
        for fpath in idx['folders']:
            if fpath == old_vpath:
                new_folders[new_vpath] = True
            elif fpath.startswith(old_prefix):
                new_folders[new_prefix + fpath[len(old_prefix):]] = True
            else:
                new_folders[fpath] = True
        idx['files'] = new_files
        idx['folders'] = new_folders
        self.audit.add(f"重命名文件夹 '{old_vpath}' -> '{new_vpath}'")
        self.save_index(idx)
        return True

    def pack_header(self) -> bytes:
        buf = bytearray(HEADER_SIZE)
        struct.pack_into(FMT_HEADER, buf, 0,
                         MAGIC, VERSION, b'\0'*32, self.lock_key, self.salt)
        num = min(len(self.partitions), MAX_PARTITIONS)
        struct.pack_into('<B', buf, 105, num)
        off = 106
        for p in self.partitions[:num]:
            alias = p['alias'][:16].encode().ljust(16, b'\0')
            tag = p['auth_tag'][:32].ljust(32, b'\0')
            struct.pack_into(FMT_PART, buf, off,
                             alias, tag,
                             p['index_offset'], p['index_length'],
                             b'\0'*16)
            off += PARTITION_ENTRY_SIZE
        struct.pack_into(FMT_LOCK, buf, LOCK_OFFSET,
                         self.lock_count & 0xFF, self.lock_until)
        lock_hmac = compute_lock_hmac(self.lock_key, self.lock_count, self.lock_until)
        struct.pack_into('<32s', buf, LOCK_OFFSET+9, lock_hmac)
        return bytes(buf)

    def unpack_header(self, data: bytes) -> bool:
        if len(data) < HEADER_SIZE:
            return False
        magic, version, _, lock_key, salt = struct.unpack_from(FMT_HEADER, data, 0)
        if magic != MAGIC or version != VERSION:
            return False
        self.lock_key = lock_key
        self.salt = salt
        num = struct.unpack_from('<B', data, 105)[0]
        self.partitions.clear()
        off = 106
        for _ in range(min(num, MAX_PARTITIONS)):
            alias_raw, tag_raw, idx_off, idx_len, _ = struct.unpack_from(FMT_PART, data, off)
            alias = alias_raw.decode('utf-8').rstrip('\0')
            self.partitions.append({
                'alias': alias,
                'auth_tag': tag_raw,
                'index_offset': idx_off,
                'index_length': idx_len
            })
            off += PARTITION_ENTRY_SIZE
        lc, lu = struct.unpack_from(FMT_LOCK, data, LOCK_OFFSET)
        stored_lock_hmac = struct.unpack_from('<32s', data, LOCK_OFFSET+9)[0]
        if not verify_lock_hmac(self.lock_key, lc, lu, stored_lock_hmac):
            return False
        self.lock_count = lc
        self.lock_until = lu
        return True

    def check_lock(self) -> bool:
        if self.lock_until == 0:
            return True
        if time.time() < self.lock_until:
            return False
        self.lock_count = 0
        self.lock_until = 0.0
        self._write_lock()
        return True

    def record_failure(self):
        self.lock_count += 1
        if self.lock_count >= MAX_ERRORS:
            self.lock_until = time.time() + LOCKOUT_SECONDS
        self._write_lock()

    def _write_lock(self):
        if not self.vault.handle:
            return
        lock_hmac = compute_lock_hmac(self.lock_key, self.lock_count, self.lock_until)
        buf = bytearray(self.vault.read_header())
        struct.pack_into(FMT_LOCK_BLOCK, buf, LOCK_OFFSET,
                         self.lock_count & 0xFF, self.lock_until, lock_hmac)
        self.vault.write_header(bytes(buf))

    def _update_header_sig(self):
        if not self.sign_key or not self.vault.handle:
            return
        header_raw = self.pack_header()
        sig = compute_header_signature(header_raw[:SIGNED_LENGTH], self.sign_key)
        full = header_raw[:SIGNATURE_OFFSET] + sig
        self.vault.write_header(full)

    def create(self, path: str, password: str, key_file_data: Optional[bytes] = None):
        self.vault = VaultFile(path)
        self.vault.open('wb+')
        self.vault.write_header(b'\0' * HEADER_SIZE)
        self.salt = token_bytes(32)
        self.lock_key = token_bytes(32)
        self.key_file_data = key_file_data
        enc_k, auth_k, sign_k = derive_keys(password, key_file_data, self.salt)
        tag = create_auth_tag(auth_k)
        empty_idx = json.dumps({'files': {}, 'folders': {}, 'audit': []}).encode()
        enc_idx = encrypt_gcm(enc_k, empty_idx)
        idx_off = self.vault.append(enc_idx)
        idx_len = len(enc_idx)
        self.partitions = [{
            'alias': DEFAULT_PARTITION,
            'auth_tag': tag,
            'index_offset': idx_off,
            'index_length': idx_len
        }]
        self.lock_count = 0
        self.lock_until = 0.0
        header_raw = self.pack_header()
        sig = compute_header_signature(header_raw[:SIGNED_LENGTH], sign_k)
        header_signed = header_raw[:SIGNATURE_OFFSET] + sig
        self.vault.write_header(header_signed)
        self.vault.close()

    def open_and_authenticate(self, path: str, password: str,
                              key_file_data: Optional[bytes] = None) -> Optional[int]:
        now = time.time()
        if now - self.last_attempt_time < COOLDOWN_SECONDS:
            return None
        self.last_attempt_time = now
        self.vault = VaultFile(path)
        self.vault.open('rb+')
        header = self.vault.read_header()
        if not self.unpack_header(header):
            self.vault.close()
            return None
        if not self.check_lock():
            self.vault.close()
            return None
        enc_k, auth_k, sign_k = derive_keys(password, key_file_data, self.salt)
        for idx, p in enumerate(self.partitions):
            if verify_auth_tag(auth_k, p['auth_tag']):
                enc_idx = self.vault.read_at(p['index_offset'], p['index_length'])
                idx_plain = decrypt_gcm(enc_k, enc_idx)
                if idx_plain is None:
                    continue
                self.active_idx = idx
                self.enc_key = enc_k
                self.auth_key = auth_k
                self.sign_key = sign_k
                self.key_file_data = key_file_data
                idx_data = json.loads(idx_plain)
                self.audit = AuditLog.from_json(idx_data.get('audit', []), auth_k)
                self.audit.add("保险柜已解锁")
                self.lock_count = 0
                self.lock_until = 0.0
                self._write_lock()
                self._update_header_sig()
                return idx
        self.record_failure()
        self.vault.close()
        return None

    def add_partition(self, alias: str, fake_pwd: str,
                      key_file_data: Optional[bytes]) -> bool:
        if not self.enc_key or not self.vault.handle:
            return False
        fake_enc, fake_auth, _ = derive_keys(fake_pwd, key_file_data, self.salt)
        tag = create_auth_tag(fake_auth)
        empty_idx = json.dumps({'files': {}, 'folders': {}, 'audit': []}).encode()
        enc_idx = encrypt_gcm(fake_enc, empty_idx)
        off = self.vault.append(enc_idx)
        if len(self.partitions) >= MAX_PARTITIONS:
            return False
        self.partitions.append({
            'alias': alias,
            'auth_tag': tag,
            'index_offset': off,
            'index_length': len(enc_idx)
        })
        self._update_header_sig()
        self.audit.add(f"添加伪装分区 '{alias}'")
        return True

    def remove_partition(self, alias_or_idx) -> bool:
        if not self.enc_key or not self.vault.handle:
            return False
        idx = -1
        if isinstance(alias_or_idx, int):
            idx = alias_or_idx
        else:
            for i, p in enumerate(self.partitions):
                if p['alias'] == alias_or_idx:
                    idx = i
                    break
        if idx <= 0 or idx >= len(self.partitions):
            return False
        part = self.partitions[idx]
        self.vault.write_at(part['index_offset'],
                            token_bytes(part['index_length']))
        del self.partitions[idx]
        self._update_header_sig()
        self.audit.add(f"删除分区 '{part['alias']}'")
        return True

    def load_index(self) -> dict:
        if not self.enc_key or not self.vault.handle:
            return {}
        p = self.partitions[self.active_idx]
        enc = self.vault.read_at(p['index_offset'], p['index_length'])
        plain = decrypt_gcm(self.enc_key, enc)
        if plain is None:
            return {}
        return json.loads(plain)

    def save_index(self, index_dict: dict):
        if not self.enc_key or not self.vault.handle:
            return
        index_dict['audit'] = self.audit.to_json()
        plain = json.dumps(index_dict).encode()
        enc = encrypt_gcm(self.enc_key, plain)
        p = self.partitions[self.active_idx]
        old_off = p['index_offset']
        old_len = p['index_length']
        new_off = self.vault.append(enc)
        p['index_offset'] = new_off
        p['index_length'] = len(enc)
        self.vault.write_at(old_off, token_bytes(old_len))
        self._update_header_sig()

    def import_file(self, src_path: str, vpath: str) -> bool:
        if not self.enc_key or not self.vault.handle or not validate_vpath(vpath):
            return False
        with open(src_path, 'rb') as f:
            content = f.read()
        enc = encrypt_gcm(self.enc_key, content)
        off = self.vault.append(enc)
        idx = self.load_index()
        dirs = vpath.split('/')
        if len(dirs) > 1:
            parent = '/'.join(dirs[:-1])
            if parent not in idx['folders']:
                idx['folders'][parent] = True
        idx['files'][vpath] = {
            'name': os.path.basename(src_path),
            'size': len(content),
            'offset': off,
            'length': len(enc)
        }
        self.audit.add(f"导入文件 '{vpath}'")
        self.save_index(idx)
        return True

    def import_folder(self, src: str, base: str):
        src_path = Path(src)
        base_name = src_path.name
        base_clean = base.rstrip('/')
        for root, dirs, files in os.walk(src_path):
            rel = os.path.relpath(root, src_path)
            if rel == '.':
                cur = f"{base_clean}/{base_name}"
            else:
                rel_path = rel.replace(os.sep, '/')
                cur = f"{base_clean}/{base_name}/{rel_path}"
            for f in files:
                full = os.path.join(root, f)
                vp = f"{cur}/{f}" if cur != '/' else f"/{f}"
                self.import_file(full, vp)
        self.audit.add(f"导入文件夹 '{base_name}'")

    def extract_file(self, vpath: str, dest_folder: str) -> bool:
        idx = self.load_index()
        if vpath not in idx['files']:
            return False
        meta = idx['files'][vpath]
        enc = self.vault.read_at(meta['offset'], meta['length'])
        plain = decrypt_gcm(self.enc_key, enc)
        if plain is None:
            return False
        dest = os.path.join(dest_folder, meta['name'])
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, 'wb') as f:
            f.write(plain)
        self.audit.add(f"提取文件 '{vpath}'")
        return True

    def delete_file(self, vpath: str):
        idx = self.load_index()
        if vpath not in idx['files']:
            return
        meta = idx['files'][vpath]
        self.vault.write_at(meta['offset'], token_bytes(meta['length']))
        del idx['files'][vpath]
        self.audit.add(f"安全删除文件 '{vpath}'")
        self.save_index(idx)

    def new_folder(self, vpath: str):
        if not validate_vpath(vpath):
            return
        idx = self.load_index()
        idx['folders'][vpath] = True
        self.audit.add(f"新建文件夹 '{vpath}'")
        self.save_index(idx)

    def delete_folder(self, vpath: str):
        idx = self.load_index()
        if vpath not in idx['folders']:
            return
        to_delete = [f for f in idx['files'] if f.startswith(vpath + '/')]
        for f in to_delete:
            self.delete_file(f)
        sub_dirs = [d for d in idx['folders'] if d.startswith(vpath + '/')]
        for d in sub_dirs:
            del idx['folders'][d]
        if vpath != '/':
            del idx['folders'][vpath]
        self.audit.add(f"删除文件夹 '{vpath}'")
        self.save_index(idx)

    def load_file_data(self, vpath: str) -> Optional[bytearray]:
        idx = self.load_index()
        if vpath not in idx['files']:
            return None
        meta = idx['files'][vpath]
        enc = self.vault.read_at(meta['offset'], meta['length'])
        plain = decrypt_gcm(self.enc_key, enc)
        if plain is None:
            return None
        return bytearray(plain)

# ---------- 安全照片查看器 ----------
class SecurePhotoViewer(QMainWindow):
    def __init__(self, core: VaultCore, img_paths: List[str], start_idx: int = 0):
        super().__init__()
        self.core = core
        self.img_paths = img_paths
        self.current_idx = start_idx
        self._rotation = 0
        self._fit_to_window = True
        self._current_pixmap = QPixmap()
        self._slide_timer = QTimer(self)
        self._slide_timer.timeout.connect(self.next_image)
        self._slide_active = False
        self._setup_ui()
        self.load_current_image()
        self.setAttribute(Qt.WA_DeleteOnClose)

    def _setup_ui(self):
        self.setWindowTitle("安全照片浏览 - 仅内存，无缓存")
        self.setMinimumSize(800, 600)
        self.img_label = QLabel()
        self.img_label.setAlignment(Qt.AlignCenter)
        self.img_label.setStyleSheet("background-color: black;")
        self.setCentralWidget(self.img_label)
        toolbar = QToolBar("浏览")
        self.addToolBar(toolbar)
        act_prev = QAction("上一张", self)
        act_prev.triggered.connect(self.prev_image)
        toolbar.addAction(act_prev)
        act_next = QAction("下一张", self)
        act_next.triggered.connect(self.next_image)
        toolbar.addAction(act_next)
        toolbar.addSeparator()
        self.act_slide = QAction("幻灯片(3s)", self)
        self.act_slide.setCheckable(True)
        self.act_slide.toggled.connect(self.toggle_slideshow)
        toolbar.addAction(self.act_slide)
        toolbar.addSeparator()
        act_fit = QAction("适应窗口", self)
        act_fit.triggered.connect(self.toggle_fit)
        toolbar.addAction(act_fit)
        act_rotate = QAction("旋转90°", self)
        act_rotate.triggered.connect(self.rotate_image)
        toolbar.addAction(act_rotate)
        act_orig = QAction("原始大小", self)
        act_orig.triggered.connect(self.show_original)
        toolbar.addAction(act_orig)
        toolbar.addSeparator()
        act_close = QAction("关闭", self)
        act_close.triggered.connect(self.close)
        toolbar.addAction(act_close)
        self.setAcceptDrops(False)

    def load_current_image(self):
        if self.current_idx < 0 or self.current_idx >= len(self.img_paths):
            self.img_label.setText("没有图片")
            self._current_pixmap = QPixmap()
            return
        vpath = self.img_paths[self.current_idx]
        data = self.core.load_file_data(vpath)
        if data is None:
            self.img_label.setText("解密失败或文件不存在")
            self._current_pixmap = QPixmap()
            return
        img = QImage()
        if not img.loadFromData(data):
            self._secure_wipe(data)
            self.img_label.setText("无法识别的图片格式")
            self._current_pixmap = QPixmap()
            return
        self._secure_wipe(data)
        if self._rotation != 0:
            transform = QTransform().rotate(self._rotation)
            img = img.transformed(transform)
        self._current_pixmap = QPixmap.fromImage(img)
        self._update_display()
        self.setWindowTitle(f"安全浏览: {os.path.basename(vpath)} ({self.current_idx+1}/{len(self.img_paths)})")

    def _update_display(self):
        if self._current_pixmap.isNull():
            return
        if self._fit_to_window:
            pix = self._current_pixmap.scaled(
                self.img_label.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation)
        else:
            pix = self._current_pixmap
        self.img_label.setPixmap(pix)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self._fit_to_window and hasattr(self, '_current_pixmap'):
            self._update_display()

    def _secure_wipe(self, data: bytearray):
        if data:
            data[:] = b'\x00' * len(data)
            del data

    def next_image(self):
        if self.current_idx < len(self.img_paths) - 1:
            self.current_idx += 1
            self._rotation = 0
            self.load_current_image()

    def prev_image(self):
        if self.current_idx > 0:
            self.current_idx -= 1
            self._rotation = 0
            self.load_current_image()

    def toggle_slideshow(self, checked: bool):
        if checked:
            self._slide_timer.start(3000)
        else:
            self._slide_timer.stop()

    def toggle_fit(self):
        self._fit_to_window = not self._fit_to_window
        self._update_display()

    def rotate_image(self):
        if self._current_pixmap.isNull():
            return
        img = self._current_pixmap.toImage()
        transform = QTransform().rotate(90)
        img = img.transformed(transform)
        self._current_pixmap = QPixmap.fromImage(img)
        self._rotation = (self._rotation + 90) % 360
        self._update_display()

    def show_original(self):
        self._fit_to_window = False
        self._update_display()

    def closeEvent(self, event):
        self._slide_timer.stop()
        self._current_pixmap = QPixmap()
        self.img_label.clear()
        super().closeEvent(event)

# ---------- 自动换行布局 ----------
class FlowLayout(QLayout):
    def __init__(self, parent=None, margin=-1, hSpacing=-1, vSpacing=-1):
        super().__init__(parent)
        self.setContentsMargins(margin, margin, margin, margin)
        self.setSpacing(hSpacing if hSpacing >= 0 else -1)
        self.itemList = []

    def addItem(self, item):
        self.itemList.append(item)

    def horizontalSpacing(self):
        if self.spacing() >= 0:
            return self.spacing()
        return self.smartSpacing(QStyle.PM_LayoutHorizontalSpacing)

    def verticalSpacing(self):
        if self.spacing() >= 0:
            return self.spacing()
        return self.smartSpacing(QStyle.PM_LayoutVerticalSpacing)

    def smartSpacing(self, pm):
        if parent := self.parent():
            return parent.style().pixelMetric(pm, None, parent)
        return -1

    def count(self):
        return len(self.itemList)

    def itemAt(self, index):
        if 0 <= index < len(self.itemList):
            return self.itemList[index]
        return None

    def takeAt(self, index):
        if 0 <= index < len(self.itemList):
            return self.itemList.pop(index)
        return None

    def expandingDirections(self):
        return Qt.Orientations(Qt.Orientation(0))

    def hasHeightForWidth(self):
        return True

    def heightForWidth(self, width):
        return self.doLayout(QRect(0, 0, width, 0), True)

    def setGeometry(self, rect):
        super().setGeometry(rect)
        self.doLayout(rect, False)

    def sizeHint(self):
        return self.minimumSize()

    def minimumSize(self):
        size = QSize()
        for item in self.itemList:
            size = size.expandedTo(item.minimumSize())
        margins = self.contentsMargins()
        size += QSize(margins.left() + margins.right(), margins.top() + margins.bottom())
        return size

    def doLayout(self, rect, testOnly):
        left, top, right, bottom = self.getContentsMargins()
        effectiveRect = rect.adjusted(+left, +top, -right, -bottom)
        x = effectiveRect.x()
        y = effectiveRect.y()
        lineHeight = 0

        for item in self.itemList:
            if not item.isEmpty():
                wid = item.widget()
                spaceX = self.horizontalSpacing()
                if spaceX == -1:
                    spaceX = 0
                spaceY = self.verticalSpacing()
                if spaceY == -1:
                    spaceY = 0
                nextX = x + item.sizeHint().width() + spaceX
                if nextX > effectiveRect.right() and lineHeight > 0:
                    x = effectiveRect.x()
                    y = y + lineHeight + spaceY
                    nextX = x + item.sizeHint().width() + spaceX
                    lineHeight = 0
                if not testOnly:
                    item.setGeometry(QRect(QPoint(x, y), item.sizeHint()))
                x = nextX
                lineHeight = max(lineHeight, item.sizeHint().height())
        return y + lineHeight - rect.y() + bottom - top

# ---------- 文件列表模型 ----------
class FileListModel(QStandardItemModel):
    _folder_icon = None
    _file_icon = None

    @classmethod
    def init_icons(cls):
        if cls._folder_icon is None:
            style = QApplication.style()
            cls._folder_icon = style.standardIcon(QStyle.StandardPixmap.SP_DirIcon)
            cls._file_icon   = style.standardIcon(QStyle.StandardPixmap.SP_FileIcon)

    def __init__(self, core: VaultCore):
        super().__init__()
        self.core = core
        self.init_icons()

    def reload(self, folder: str):
        self.clear()
        idx = self.core.load_index()
        for fpath in idx.get('folders', {}):
            if fpath == '/' or fpath == '':
                continue
            parent = fpath.rsplit('/', 1)[0] if '/' in fpath else '/'
            if parent == '':
                parent = '/'
            if parent == folder:
                name = fpath.split('/')[-1]
                if not name:
                    continue
                item = QStandardItem(name)
                item.setData(fpath, Qt.UserRole)
                item.setData('folder', Qt.UserRole + 1)
                item.setIcon(self._folder_icon)
                self.appendRow(item)
        for vpath, meta in idx.get('files', {}).items():
            dir_part = vpath.rsplit('/', 1)[0] if '/' in vpath else '/'
            if dir_part == folder or (folder == '/' and dir_part == ''):
                name = meta.get('name', '')
                if not name:
                    continue
                item = QStandardItem(name)
                item.setData(vpath, Qt.UserRole)
                item.setData('file', Qt.UserRole + 1)
                item.setIcon(self._file_icon)
                self.appendRow(item)

# ---------- 主窗口（无菜单栏，工具栏换行，正方形居中）----------
class VaultMainWindow(QMainWindow):
    def __init__(self):
        self.core = VaultCore()
        self.vault_path = None
        self.current_folder = '/'
        self.photo_viewer = None
        self.destroy_btn = None
        self._init_ui()
        self._update_actions()

    def _init_ui(self):
        super().__init__()
        self.setWindowTitle("LynVault 1.2.2")
        
        # 根据屏幕大小自动计算正方形边长并居中
        screen_geometry = QApplication.primaryScreen().availableGeometry()
        screen_width = screen_geometry.width()
        screen_height = screen_geometry.height()
        size = int(min(screen_width, screen_height) * 0.75)
        self.resize(size, size)
        x = (screen_width - size) // 2 + screen_geometry.x()
        y = (screen_height - size) // 2 + screen_geometry.y()
        self.move(x, y)

        icon_path = os.path.join(os.path.dirname(__file__), "icon.ico")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        # ---------- 先创建所有 QAction ----------
        self.act_create = QAction("新建保险柜...", self)
        self.act_create.triggered.connect(self.create_vault)

        self.act_open = QAction("打开保险柜...", self)
        self.act_open.triggered.connect(self.open_vault)

        self.act_close = QAction("关闭保险柜", self)
        self.act_close.triggered.connect(self.close_vault)

        self.act_add_part = QAction("添加伪装分区", self)
        self.act_add_part.triggered.connect(self.add_partition)

        self.act_del_part = QAction("删除伪装分区", self)
        self.act_del_part.triggered.connect(self.remove_partition)

        self.act_import_f = QAction("导入文件", self)
        self.act_import_f.triggered.connect(self.import_files)

        self.act_import_d = QAction("导入文件夹", self)
        self.act_import_d.triggered.connect(self.import_folder)

        self.act_extract = QAction("提取选中", self)
        self.act_extract.triggered.connect(self.extract_selected)

        self.act_delete = QAction("安全删除", self)
        self.act_delete.triggered.connect(self.delete_selected)

        self.act_newdir = QAction("新建文件夹", self)
        self.act_newdir.triggered.connect(self.new_folder)

        self.act_browse_photos = QAction("安全浏览照片", self)
        self.act_browse_photos.triggered.connect(self.browse_photos)

        self.act_audit = QAction("查看审计日志", self)
        self.act_audit.triggered.connect(self.show_audit)

        # ---------- 菜单栏已删除，不再创建 ----------

        # ---------- 可换行的工具栏区域 ----------
        toolbar_widget = QWidget()
        toolbar_layout = FlowLayout(toolbar_widget)

        actions_info = [
            (self.act_create, False),
            (self.act_open, False),
            (self.act_close, False),
            (None, True),
            (self.act_add_part, False),
            (self.act_del_part, False),
            (None, True),
            (self.act_import_f, False),
            (self.act_import_d, False),
            (self.act_extract, False),
            (self.act_delete, False),
            (self.act_newdir, False),
            (self.act_browse_photos, False),
            (None, True),
            (self.act_audit, False),
        ]

        self.tool_buttons = []
        for action, is_sep in actions_info:
            if is_sep:
                sep_label = QLabel("  ")
                toolbar_layout.addWidget(sep_label)
            elif action:
                btn = QToolButton()
                btn.setDefaultAction(action)
                btn.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
                toolbar_layout.addWidget(btn)
                self.tool_buttons.append(btn)

        # 红色销毁按钮
        self.destroy_btn = QPushButton("销毁保险箱")
        self.destroy_btn.setStyleSheet("color: red; font-weight: bold;")
        self.destroy_btn.clicked.connect(self.destroy_vault)
        toolbar_layout.addWidget(self.destroy_btn)

        # ---------- 中央区域 ----------
        central = QWidget()
        main_layout = QVBoxLayout(central)
        main_layout.addWidget(toolbar_widget)

        # 导航栏（初始隐藏）
        self.nav_widget = QWidget()
        nav_layout = QHBoxLayout(self.nav_widget)
        nav_layout.setContentsMargins(0, 0, 0, 0)
        self.up_btn = QPushButton()
        self.up_btn.setIcon(self.style().standardIcon(QStyle.SP_ArrowUp))
        self.up_btn.setToolTip("向上")
        self.up_btn.clicked.connect(self.go_up)
        nav_layout.addWidget(self.up_btn)
        self.path_edit = QLineEdit("/")
        self.path_edit.returnPressed.connect(self.on_path_enter)
        nav_layout.addWidget(self.path_edit, 1)
        self.nav_widget.setVisible(False)
        main_layout.addWidget(self.nav_widget)

        # 文件列表视图
        self.list = QListView()
        self.file_model = FileListModel(self.core)
        self.list.setModel(self.file_model)
        self.list.setViewMode(QListView.ListMode)
        self.list.setWrapping(False)
        self.list.setResizeMode(QListView.Adjust)
        self.list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.list.customContextMenuRequested.connect(self.file_context_menu)
        self.list.doubleClicked.connect(self.on_list_double_clicked)
        main_layout.addWidget(self.list)

        self.setCentralWidget(central)

        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.status.showMessage("开源地址：https://github.com/lynvortex/LynVault")
        self.setAcceptDrops(True)

    def _update_actions(self):
        enabled = self.vault_path is not None
        for a in [
            self.act_close, self.act_add_part, self.act_del_part,
            self.act_import_f, self.act_import_d, self.act_extract,
            self.act_delete, self.act_newdir, self.act_audit,
            self.act_browse_photos,
        ]:
            a.setEnabled(enabled)
        if self.destroy_btn:
            self.destroy_btn.setEnabled(enabled)
        if self.up_btn:
            self.up_btn.setEnabled(enabled)
        if self.nav_widget:
            self.nav_widget.setVisible(enabled)

    def _get_key_file(self) -> Optional[bytes]:
        dlg = QMessageBox(self)
        dlg.setWindowTitle("密钥文件")
        dlg.setText("是否使用密钥文件作为第二因素？")
        dlg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        dlg.setDefaultButton(QMessageBox.No)
        if dlg.exec() == QMessageBox.Yes:
            path, _ = QFileDialog.getOpenFileName(self, "选择密钥文件", "",
                                                   "所有文件 (*)")
            if path:
                with open(path, 'rb') as f:
                    return f.read()
        return None

    def create_vault(self):
        path, _ = QFileDialog.getSaveFileName(self, "新建保险柜", "",
                                               "Vault Files (*.vault)")
        if not path:
            return
        pwd, ok = QInputDialog.getText(self, "设置主密码",
                                        "主密码（至少12位）:",
                                        QLineEdit.Password)
        if not ok or not pwd:
            return
        if len(pwd) < 12:
            QMessageBox.warning(self, "弱密码", "要求密码长度至少12位")
            return
        key_data = self._get_key_file()
        try:
            self.core.create(path, pwd, key_data)
            QMessageBox.information(self, "完成", f"保险柜已创建于:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "错误", str(e))

    def open_vault(self):
        path, _ = QFileDialog.getOpenFileName(self, "打开保险柜", "",
                                               "Vault Files (*.vault)")
        if not path:
            return
        pwd, ok = QInputDialog.getText(self, "输入密码", "密码:",
                                        QLineEdit.Password)
        if not ok:
            return
        key_data = self._get_key_file()
        idx = self.core.open_and_authenticate(path, pwd, key_data)
        if idx is None:
            QMessageBox.critical(self, "认证失败",
                                 "密码/密钥文件错误，或保险柜已锁定")
            return
        self.vault_path = path
        self.navigate_to('/')
        part_name = self.core.partitions[idx]['alias']
        self.status.showMessage(f"已解锁分区: {part_name}  | 审计日志已激活")
        self._update_actions()

    def close_vault(self):
        if self.core.audit:
            self.core.audit.add("保险柜关闭")
            idx = self.core.load_index()
            self.core.save_index(idx)
        if self.core.vault.handle:
            self.core.vault.close()
        self.core = VaultCore()
        self.vault_path = None
        self.current_folder = '/'
        self.file_model = FileListModel(self.core)
        self.list.setModel(self.file_model)
        self._update_actions()
        self.status.showMessage("保险柜已关闭")

    def destroy_vault(self):
        if not self.vault_path:
            return
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Warning)
        msg.setWindowTitle("销毁保险箱")
        msg.setText("⚠️ 该操作不可逆，保险箱文件将被永久销毁！\n\n确定要继续吗？")
        msg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        msg.setDefaultButton(QMessageBox.No)
        msg.setStyleSheet("QLabel{color: red; font-weight: bold;}")
        if msg.exec() != QMessageBox.Yes:
            return
        if self.core.vault.handle:
            self.core.vault.close()
        self.core = VaultCore()
        vault_path = self.vault_path
        self.vault_path = None
        progress = QProgressDialog("正在安全销毁保险箱...", None, 0, 100, self)
        progress.setWindowTitle("销毁中")
        progress.setCancelButton(None)
        progress.show()
        def update_progress(val):
            progress.setValue(val)
            QApplication.processEvents()
        try:
            dod_erase(vault_path, update_progress)
        except Exception as e:
            QMessageBox.critical(self, "销毁失败", f"无法销毁文件：{str(e)}")
            progress.close()
            return
        progress.setValue(100)
        self.current_folder = '/'
        self.file_model = FileListModel(self.core)
        self.list.setModel(self.file_model)
        self._update_actions()
        self.status.showMessage("保险箱已销毁")
        QMessageBox.information(self, "完成", "保险箱文件已安全销毁。")

    def navigate_to(self, folder_path: str):
        self.current_folder = folder_path
        self.path_edit.setText(folder_path)
        self.file_model.reload(folder_path)
        self.up_btn.setEnabled(folder_path != '/')

    def go_up(self):
        if self.current_folder == '/':
            return
        parent = self.current_folder.rsplit('/', 1)[0]
        if parent == '':
            parent = '/'
        self.navigate_to(parent)

    def on_path_enter(self):
        path = self.path_edit.text().strip()
        if not path.startswith('/'):
            path = '/' + path
        if not validate_vpath(path):
            QMessageBox.warning(self, "路径无效", "输入的路径包含非法字符")
            self.path_edit.setText(self.current_folder)
            return
        idx = self.core.load_index()
        if path != '/' and path not in idx.get('folders', {}):
            QMessageBox.warning(self, "路径不存在", f"文件夹 '{path}' 不存在")
            self.path_edit.setText(self.current_folder)
            return
        self.navigate_to(path)

    def on_list_double_clicked(self, index):
        item = self.file_model.itemFromIndex(index)
        if not item:
            return
        entry_type = item.data(Qt.UserRole + 1)
        if entry_type != 'folder':
            return
        folder_path = item.data(Qt.UserRole)
        self.navigate_to(folder_path)

    def import_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "导入文件")
        for f in files:
            vp = self.current_folder.rstrip('/') + '/' + os.path.basename(f)
            success = self.core.import_file(f, vp)
            if success:
                reply = QMessageBox.question(
                    self, "粉碎原文件",
                    f"文件 '{os.path.basename(f)}' 已导入。\n是否安全粉碎原文件（7次擦除）？",
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No
                )
                if reply == QMessageBox.Yes:
                    progress = QProgressDialog(f"正在粉碎 {os.path.basename(f)}...", None, 0, 100, self)
                    progress.setWindowTitle("粉碎文件")
                    progress.setCancelButton(None)
                    progress.show()
                    def update_progress(val):
                        progress.setValue(val)
                        QApplication.processEvents()
                    try:
                        dod_erase(f, update_progress)
                    except Exception as e:
                        QMessageBox.warning(self, "粉碎失败", f"无法粉碎 {f}: {str(e)}")
                    progress.close()
        self.file_model.reload(self.current_folder)

    def import_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "导入文件夹")
        if not folder:
            return
        self.core.import_folder(folder, self.current_folder.rstrip('/'))
        self.file_model.reload(self.current_folder)

    def extract_selected(self):
        idxs = self.list.selectedIndexes()
        if not idxs:
            return
        dest = QFileDialog.getExistingDirectory(self, "提取到")
        if not dest:
            return
        for idx in idxs:
            vp = idx.data(Qt.UserRole)
            if vp:
                self.core.extract_file(vp, dest)
        QMessageBox.information(self, "完成", "提取完成")

    def delete_selected(self):
        idxs = self.list.selectedIndexes()
        if not idxs:
            return
        reply = QMessageBox.question(self, "确认",
                                     "确定安全删除所选文件吗？此操作不可逆！",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        for idx in idxs:
            vp = idx.data(Qt.UserRole)
            if vp:
                self.core.delete_file(vp)
        self.file_model.reload(self.current_folder)

    def new_folder(self):
        name, ok = QInputDialog.getText(self, "新建文件夹", "文件夹名称（禁止 ..）:")
        if not ok or not name or not name.strip():
            return
        name = name.strip()
        if '/' in name or '\\' in name or '..' in name:
            QMessageBox.warning(self, "非法字符", "名称不能包含 / \\ .. 等字符")
            return
        vp = self.current_folder.rstrip('/') + '/' + name
        if not validate_vpath(vp):
            QMessageBox.warning(self, "非法路径", "路径包含不安全字符")
            return
        self.core.new_folder(vp)
        self.file_model.reload(self.current_folder)

    def add_partition(self):
        if not self.vault_path:
            return
        alias, ok = QInputDialog.getText(self, "别名", "伪装分区名称:")
        if not ok:
            return
        fpwd, ok = QInputDialog.getText(self, "伪装密码",
                                         "设置伪装分区密码（至少12位）:",
                                         QLineEdit.Password)
        if not ok:
            return
        if len(fpwd) < 12:
            QMessageBox.warning(self, "弱密码", "伪装密码长度不足")
            return
        key_data = self._get_key_file()
        if self.core.add_partition(alias, fpwd, key_data):
            QMessageBox.information(self, "成功", f"伪装分区 '{alias}' 已添加")
        else:
            QMessageBox.critical(self, "错误", "添加失败")

    def remove_partition(self):
        if not self.vault_path:
            return
        parts = self.core.partitions[1:]
        if not parts:
            QMessageBox.information(self, "提示", "没有可删除的伪装分区")
            return
        items = [p['alias'] for p in parts]
        item, ok = QInputDialog.getItem(self, "删除分区", "选择分区:",
                                         items, 0, False)
        if not ok:
            return
        if QMessageBox.question(self, "确认",
                                f"确定删除分区 '{item}' 吗？") != QMessageBox.Yes:
            return
        if self.core.remove_partition(item):
            QMessageBox.information(self, "成功", f"分区 '{item}' 已删除")
        else:
            QMessageBox.critical(self, "错误", "删除失败")

    def show_audit(self):
        if not self.core.audit:
            QMessageBox.information(self, "审计日志", "日志不可用")
            return
        entries = self.core.audit.to_json()
        if not entries:
            QMessageBox.information(self, "审计日志", "暂无操作记录")
            return
        text = "\n".join([f"{e['ts']:.0f}: {e['event']}" for e in entries])
        QMessageBox.information(self, "审计日志 (防篡改)", text[:4000])

    def browse_photos(self):
        if not self.vault_path:
            return
        selected_indexes = self.list.selectedIndexes()
        if selected_indexes:
            paths = [idx.data(Qt.UserRole) for idx in selected_indexes if idx.data(Qt.UserRole)]
        else:
            paths = []
            idx = self.core.load_index()
            folder_prefix = self.current_folder.rstrip('/') + '/'
            for vpath in idx.get('files', {}):
                if vpath.startswith(folder_prefix):
                    paths.append(vpath)
        if not paths:
            QMessageBox.information(self, "提示", "没有可浏览的文件")
            return
        img_exts = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.tiff', '.tif'}
        img_paths = [p for p in paths if os.path.splitext(p)[1].lower() in img_exts]
        if not img_paths:
            QMessageBox.information(self, "提示", "当前选择/文件夹中没有图片文件")
            return
        self.photo_viewer = SecurePhotoViewer(self.core, img_paths)
        self.photo_viewer.destroyed.connect(self._on_viewer_closed)
        self.photo_viewer.show()

    def _on_viewer_closed(self):
        self.photo_viewer = None

    def file_context_menu(self, pos):
        menu = QMenu()
        act_ext = menu.addAction("提取")
        act_del = menu.addAction("安全删除")
        act_browse = menu.addAction("安全浏览")
        act_rename = menu.addAction("重命名")
        choice = menu.exec(self.list.viewport().mapToGlobal(pos))
        if choice == act_ext:
            self.extract_selected()
        elif choice == act_del:
            self.delete_selected()
        elif choice == act_browse:
            self.browse_photos()
        elif choice == act_rename:
            self.rename_selected_item()

    def rename_selected_item(self):
        selected = self.list.selectedIndexes()
        if not selected:
            return
        index = selected[0]
        item = self.file_model.itemFromIndex(index)
        if not item:
            return
        vpath = item.data(Qt.UserRole)
        entry_type = item.data(Qt.UserRole + 1)
        current_name = item.text()
        title = "重命名文件夹" if entry_type == 'folder' else "重命名文件"
        new_name, ok = QInputDialog.getText(self, title, "新名称:", text=current_name)
        if not ok or not new_name or new_name.strip() == '':
            return
        new_name = new_name.strip()
        if '/' in new_name or '\\' in new_name or '..' in new_name:
            QMessageBox.warning(self, "非法字符", "名称不能包含 / \\ .. 等字符")
            return
        success = False
        if entry_type == 'folder':
            success = self.core.rename_folder(vpath, new_name)
        else:
            success = self.core.rename_file(vpath, new_name)
        if success:
            if entry_type == 'folder':
                if self.current_folder == vpath or self.current_folder.startswith(vpath + '/'):
                    new_parent = vpath.rsplit('/', 1)[0] + '/' + new_name
                    self.current_folder = self.current_folder.replace(vpath, new_parent, 1)
            self.file_model.reload(self.current_folder)
            self.navigate_to(self.current_folder)
        else:
            QMessageBox.critical(self, "重命名失败", "可能名称冲突或路径无效")

    def dragEnterEvent(self, e: QDragEnterEvent):
        if self.vault_path and e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e: QDropEvent):
        for url in e.mimeData().urls():
            p = url.toLocalFile()
            if os.path.isfile(p):
                vp = self.current_folder.rstrip('/') + '/' + os.path.basename(p)
                success = self.core.import_file(p, vp)
                if success:
                    reply = QMessageBox.question(
                        self, "粉碎原文件",
                        f"文件 '{os.path.basename(p)}' 已导入。\n是否安全粉碎原文件（7次擦除）？",
                        QMessageBox.Yes | QMessageBox.No, QMessageBox.No
                    )
                    if reply == QMessageBox.Yes:
                        progress = QProgressDialog(f"正在粉碎 {os.path.basename(p)}...", None, 0, 100, self)
                        progress.setWindowTitle("粉碎文件")
                        progress.setCancelButton(None)
                        progress.show()
                        def update_progress(val):
                            progress.setValue(val)
                            QApplication.processEvents()
                        try:
                            dod_erase(p, update_progress)
                        except Exception as ex:
                            QMessageBox.warning(self, "粉碎失败", f"无法粉碎 {p}: {str(ex)}")
                        progress.close()
            elif os.path.isdir(p):
                self.core.import_folder(p, self.current_folder.rstrip('/'))
        self.file_model.reload(self.current_folder)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    win = VaultMainWindow()
    win.show()
    sys.exit(app.exec())
