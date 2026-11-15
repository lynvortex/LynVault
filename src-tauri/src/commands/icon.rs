//! Windows 文件类型图标（Shell 图标 → PNG data URL）—— 3.1.1 从 commands.rs 拆出。
//!
//! 纯平台代码，与保险柜会话无耦合；拆出后 commands.rs 不再需要把 GDI 句柄守卫
//! （IconGuard / BitmapGuard / DcGuard）与 45 个命令混在一起 review。

// ───────────────── 文件类型图标（Windows 系统图标） ─────────────────
// 对齐 1.3.4 的 QFileIconProvider 行为：按扩展名读取系统注册的文件类型图标。
// 仅 Windows 实现；其他平台返回空串，前端 fallback 到 emoji 图标。
//
// 2.3.0 防卡死注意点：
// - 用 SHGFI_USEFILEATTRIBUTES + 伪文件名 "dummy.ext" 查询，**不访问真实文件**
//   （不走磁盘/网络，网络驱动器也不会挂起）；
// - 命令为 async + spawn_blocking：Shell/GDI 调用在阻塞线程池执行，
//   不占用 Tauri 主线程（UI 线程），大量文件渲染时界面不会冻结。
#[tauri::command]
pub async fn get_file_icon(ext: String) -> Result<String, String> {
    // 清洗扩展名：去前导点、转小写、截断长度
    let ext = ext.trim_start_matches('.').to_lowercase();
    if ext.is_empty()
        || ext.len() > 32
        || !ext
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Ok(String::new());
    }
    #[cfg(windows)]
    {
        let ext_clone = ext.clone();
        match tauri::async_runtime::spawn_blocking(move || read_windows_file_icon(&ext_clone)).await
        {
            Ok(Ok(b64)) => Ok(b64),
            Ok(Err(e)) => {
                log::warn!("get_file_icon 失败 ({}): {}", ext, e);
                Ok(String::new())
            }
            Err(e) => {
                log::warn!("get_file_icon 任务失败: {}", e);
                Ok(String::new())
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = ext;
        Ok(String::new())
    }
}

#[cfg(windows)]
fn read_windows_file_icon(ext: &str) -> Result<String, String> {
    // 注：HICON/DestroyIcon/DeleteDC/HDC 在模块级导入（IconGuard/DcGuard 需要），
    // 此处只导入本函数内使用的项。
    use base64::{engine::general_purpose::STANDARD, Engine};
    use windows::Win32::Graphics::Gdi::{
        GetDIBits, SelectObject, BITMAPINFO, BITMAPINFOHEADER, DIB_RGB_COLORS,
    };
    use windows::Win32::UI::Shell::{
        SHGetFileInfoW, SHFILEINFOW, SHGFI_ICON, SHGFI_SMALLICON, SHGFI_USEFILEATTRIBUTES,
    };
    use windows::Win32::UI::WindowsAndMessaging::{GetIconInfo, ICONINFO};

    // 构造伪文件名 "dummy.ext" 让 Shell 按扩展名查图标
    let filename: Vec<u16> = format!("dummy.{}\0", ext).encode_utf16().collect();

    let mut shfi = SHFILEINFOW::default();
    let flags = SHGFI_ICON | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES;
    let hinst = unsafe {
        SHGetFileInfoW(
            windows::core::PCWSTR(filename.as_ptr()),
            // FILE_ATTRIBUTE_NORMAL 位于 Win32::Storage::FileSystem（windows 0.57）
            windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL,
            Some(&mut shfi),
            std::mem::size_of::<SHFILEINFOW>() as u32,
            flags,
        )
    };
    // windows 0.57 中 SHGetFileInfoW 返回 usize（成功时非 0，失败为 0）；
    // SHFILEINFOW.hIcon 是 HICON（非 Option）。
    // 3.0.0（i686 修复）：SHFILEINFOW 在 32 位目标上是 packed 结构 —— 对字段
    // 创建引用（is_invalid() 需要 &self）是未对齐引用（E0793 硬错误）；
    // 按值拷贝到局部变量（编译器生成 unaligned read）后再判断。
    let hicon: HICON = shfi.hIcon;
    if hinst == 0 || hicon.is_invalid() {
        return Err("SHGetFileInfoW 未返回图标".into());
    }

    // 取图标位图信息
    let mut icon_info = ICONINFO::default();
    let ok = unsafe { GetIconInfo(hicon, &mut icon_info) };
    let _guard = IconGuard(hicon); // 确保最后 DestroyIcon

    if ok.is_err() {
        return Err("GetIconInfo 失败".into());
    }
    // 2.8.1：RAII 接管两个位图，覆盖本函数所有早退路径
    let _bm_color = BitmapGuard(icon_info.hbmColor);
    let _bm_mask = BitmapGuard(icon_info.hbmMask);

    // 优先用 color bitmap
    let hbm = icon_info.hbmColor;
    if hbm.is_invalid() {
        return Err("图标无 color bitmap".into());
    }

    // 创建兼容 DC 并选入位图
    let hdc = unsafe { windows::Win32::Graphics::Gdi::CreateCompatibleDC(None) };
    if hdc.is_invalid() {
        return Err("CreateCompatibleDC 失败".into());
    }
    let _dc_guard = DcGuard(hdc);
    let old_bm = unsafe { SelectObject(hdc, hbm) };

    // 准备 BITMAPINFO 请求 RGBA。
    // 注意（2.3.0 修复）：尺寸查询（lpvBits=NULL）时 biBitCount 必须为 0，
    // 否则 GetDIBits 返回 0 + ERROR_INVALID_PARAMETER(87)，图标读取失败。
    let mut bi = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: 0,
            biHeight: 0,
            biPlanes: 1,
            biBitCount: 0,
            biCompression: 0, // BI_RGB
            biSizeImage: 0,
            biXPelsPerMeter: 0,
            biYPelsPerMeter: 0,
            biClrUsed: 0,
            biClrImportant: 0,
        },
        bmiColors: [Default::default()],
    };

    // 第一次调用取尺寸
    let n = unsafe { GetDIBits(hdc, hbm, 0, 0, None, &mut bi, DIB_RGB_COLORS) };
    if n == 0 {
        return Err("GetDIBits 取尺寸失败".into());
    }
    let w = bi.bmiHeader.biWidth;
    let h = bi.bmiHeader.biHeight; // 正数表示 bottom-up
    if w <= 0 || h == 0 {
        return Err("图标尺寸无效".into());
    }
    let abs_h = h.unsigned_abs();
    // 3.0.1（F14）：尺寸来自 Windows 图标缓存而非攻击者字节，但
    // overflow-checks=true 下无界乘法仍是 panic 面 —— checked + 合理上限。
    let img_size: usize = (w as usize)
        .checked_mul(abs_h as usize)
        .and_then(|v| v.checked_mul(4))
        .filter(|v| *v <= 512 * 1024 * 1024)
        .ok_or("图标尺寸异常")?;
    let mut pixels: Vec<u8> = vec![0u8; img_size];

    // 第二次调用取像素
    let n2 = unsafe {
        GetDIBits(
            hdc,
            hbm,
            0,
            abs_h,
            Some(pixels.as_mut_ptr() as *mut _),
            &mut bi,
            DIB_RGB_COLORS,
        )
    };
    if n2 == 0 {
        return Err("GetDIBits 取像素失败".into());
    }

    // 恢复 DC 旧对象
    unsafe {
        SelectObject(hdc, old_bm);
    }

    // BGRA → RGBA，并处理 bottom-up / top-down
    let bottom_up = h > 0;
    let mut rgba: Vec<u8> = Vec::with_capacity(pixels.len());
    if bottom_up {
        // 行序反转
        let row = (w as usize) * 4;
        for y in (0..abs_h as usize).rev() {
            let off = y * row;
            for px in pixels[off..off + row].chunks_exact(4) {
                rgba.push(px[2]); // R
                rgba.push(px[1]); // G
                rgba.push(px[0]); // B
                rgba.push(px[3]); // A
            }
        }
    } else {
        for px in pixels.chunks_exact(4) {
            rgba.push(px[2]);
            rgba.push(px[1]);
            rgba.push(px[0]);
            rgba.push(px[3]);
        }
    }

    // PNG 编码
    let img =
        image::RgbaImage::from_raw(w as u32, abs_h as u32, rgba).ok_or("构造 RgbaImage 失败")?;
    let mut png_buf = std::io::Cursor::new(Vec::with_capacity(4096));
    image::DynamicImage::ImageRgba8(img)
        .write_to(&mut png_buf, image::ImageFormat::Png)
        .map_err(|e| format!("PNG 编码失败: {}", e))?;

    Ok(format!(
        "data:image/png;base64,{}",
        STANDARD.encode(png_buf.into_inner())
    ))
}

// windows 0.57：HICON 位于 Win32::UI::WindowsAndMessaging（0.58+ 才移到 Foundation），
// 模块级导入供下方 RAII guard 使用
#[cfg(windows)]
use windows::Win32::Graphics::Gdi::{DeleteDC, DeleteObject, HBITMAP, HDC};
#[cfg(windows)]
use windows::Win32::UI::WindowsAndMessaging::{DestroyIcon, HICON};

/// 2.8.1：GetIconInfo 返回的 hbmColor / hbmMask 都必须 DeleteObject ——
/// 旧实现两者都不释放（每次查询新扩展名泄漏 2 个 GDI 句柄）。
#[cfg(windows)]
struct BitmapGuard(HBITMAP);
#[cfg(windows)]
impl Drop for BitmapGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = DeleteObject(windows::Win32::Graphics::Gdi::HGDIOBJ(self.0 .0));
        }
    }
}

#[cfg(windows)]
struct IconGuard(HICON);
#[cfg(windows)]
impl Drop for IconGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = DestroyIcon(self.0);
        }
    }
}

#[cfg(windows)]
struct DcGuard(HDC);
#[cfg(windows)]
impl Drop for DcGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = DeleteDC(self.0);
        }
    }
}
