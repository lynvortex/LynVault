//! 会话密钥的驻留内存封装（3.0.0 审计加固）。
//!
//! **问题**：会话密钥此前以裸 `[u8; 32]` 存于 `Vault` 结构体 —— 结构体随
//! `*guard = Some(vault)` 移动时密钥字节被 memcpy 到新地址（旧地址不经历
//! Drop，密钥残留），且 OS 可在内存压力下把含密钥的页换出到 pagefile
//!（磁盘上的可恢复明文残留，与产品的抗取证承诺冲突）。
//!
//! **方案**：密钥装箱到堆上稳定地址（Box 目标不随结构体移动），创建时
//! `VirtualLock`（Windows）/ `mlock`（Unix）钉住所在页防止换出，Drop 时
//! 先解锁再 zeroize。页级粒度（32 字节密钥锁 1 页 4KB，4 把会话密钥
//! 共 4 页）—— 工作集配额内几乎必然成功；失败时降级为「仅装箱 + Drop
//! 清零」（仍优于裸数组：地址稳定），不给开柜增加失败路径。
//!
//! 使用纪律：`Deref` 到 `[u8; 32]` —— 传参经解引用强转零成本兼容既有
//! `&[u8; 32]` API；需要值拷贝处显式 `**key`（拷贝出的副本由调用方既有
//! 的零化纪律负责，与本文件无关）。

use zeroize::Zeroize;

pub(crate) struct LockedKey {
    key: Box<[u8; 32]>,
    /// 锁页是否实际生效（失败则 Drop 跳过解锁）
    locked: bool,
}

#[cfg(windows)]
fn lock_pages(ptr: *const u8, len: usize) -> bool {
    use windows::Win32::System::Memory::VirtualLock;
    // VirtualLock 按页粒度钉住覆盖范围；工作集配额不足时失败 —— 降级可接受
    unsafe { VirtualLock(ptr as *const core::ffi::c_void, len) }.is_ok()
}

#[cfg(windows)]
fn unlock_pages(ptr: *const u8, len: usize) {
    use windows::Win32::System::Memory::VirtualUnlock;
    let _ = unsafe { VirtualUnlock(ptr as *const core::ffi::c_void, len) };
}

#[cfg(unix)]
fn lock_pages(ptr: *const u8, len: usize) -> bool {
    // mlock 同为页级粒度；RLIMIT_MEMLOCK 不足时失败 —— 降级可接受
    unsafe { libc::mlock(ptr as *const libc::c_void, len) == 0 }
}

#[cfg(unix)]
fn unlock_pages(ptr: *const u8, len: usize) {
    unsafe { libc::munlock(ptr as *const libc::c_void, len) };
}

impl LockedKey {
    pub(crate) fn new(key: [u8; 32]) -> Self {
        let key = Box::new(key);
        let locked = lock_pages(key.as_ptr(), 32);
        Self { key, locked }
    }
}

impl std::ops::Deref for LockedKey {
    type Target = [u8; 32];

    fn deref(&self) -> &[u8; 32] {
        &self.key
    }
}

impl Drop for LockedKey {
    fn drop(&mut self) {
        if self.locked {
            unlock_pages(self.key.as_ptr(), 32);
        }
        // 先解锁再清零：zeroize 触发的写不可再被换出
        self.key.zeroize();
    }
}
