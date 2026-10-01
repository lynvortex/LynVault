//! Office 文档文本提取（docx / doc / xlsx / xls / pptx / csv）
//!
//! - `.docx`：解压 ZIP → 解析 word/document.xml → 提取 <w:t> 文本节点
//! - `.doc`：OLE 复合文档 → 扫描 UTF-16LE 文本流
//! - `.xlsx/.xls`：通过 calamine 读取所有工作表
//! - `.pptx`：解压 ZIP → 解析幻灯片 XML
//! - `.csv`：直接作为 UTF-8 文本返回
//! - 加密 Office：支持 Agile Encryption（AES-CBC + PBKDF2）

use std::io::{self, Cursor, Read};
use quick_xml::Reader;
use quick_xml::events::Event;
use quick_xml::escape::resolve_xml_entity;
use calamine::Reader as CalReader;

/// 还原 quick-xml 0.41 拆分出的实体引用事件（GeneralRef）为实际字符。
///
/// 0.41 起 reader 不再把 `&amp;` 之类的实体并入 Text 事件，而是单独发出
/// `Event::GeneralRef`（内容为不含 `&`/`;` 的实体名，如 `amp`、`#x4E2D`）。
/// 这里解析预定义实体与数字字符引用；未知实体保留原始 `&name;` 形式。
fn resolve_general_ref(name: &str) -> String {
    if let Some(rest) = name.strip_prefix('#') {
        let code = if let Some(hex) = rest.strip_prefix(['x', 'X']) {
            u32::from_str_radix(hex, 16).ok()
        } else {
            rest.parse::<u32>().ok()
        };
        if let Some(c) = code.and_then(char::from_u32) {
            return c.to_string();
        }
    }
    if let Some(s) = resolve_xml_entity(name) {
        return s.to_string();
    }
    format!("&{};", name)
}

// ───────────────── 公共接口 ─────────────────

/// 预览文本总量上限（64 MiB）。2.3.0 修复：docx/pptx 是 ZIP 容器，
/// 恶意构造的「压缩炸弹」解压后可占用巨量内存导致 OOM，此处对每个条目、
/// 条目数量与最终文本总量统一设限。
const MAX_OFFICE_TEXT: usize = 64 * 1024 * 1024;

/// 2.5.1 新增：ZIP 容器条目数量上限。恶意 zip 可在中央目录声明海量条目，
/// zip crate 解析时为每个条目分配元数据，旧实现不检查条目数导致内存耗尽。
const MAX_ZIP_ENTRIES: usize = 10_000;

/// 2.5.1 新增：工作表数量上限。恶意 xlsx 可声明海量（空）工作表，
/// 每个表头行不计入文本总量上限，旧实现可被堆到千万级。
const MAX_SHEETS: usize = 1_000;

/// 2.5.1 新增：单表行数处理上限，超出即拒绝预览（防恶意大表）。
const MAX_ROWS_PER_SHEET: usize = 1_000_000;

/// 从 ZIP 归档中读取单个条目，限制解压后大小（防压缩炸弹）。
fn read_zip_entry_limited<R: Read + io::Seek>(
    archive: &mut zip::ZipArchive<R>,
    name: &str,
) -> io::Result<Vec<u8>> {
    let f = archive.by_name(name)
        .map_err(|_| io::Error::new(io::ErrorKind::NotFound, format!("{} 不存在", name)))?;
    if f.size() > MAX_OFFICE_TEXT as u64 {
        return Err(io::Error::new(io::ErrorKind::InvalidData,
            format!("条目 '{}' 解压尺寸超过预览上限（可能为压缩炸弹）", name)));
    }
    let mut buf = Vec::with_capacity(f.size() as usize);
    f.take((MAX_OFFICE_TEXT as u64) + 1).read_to_end(&mut buf)?;
    if buf.len() > MAX_OFFICE_TEXT {
        return Err(io::Error::new(io::ErrorKind::InvalidData,
            format!("条目 '{}' 解压后超过预览上限", name)));
    }
    Ok(buf)
}

/// 自动检测格式并提取 Office 文档文本
pub fn extract_office_text(data: &[u8], filename: &str) -> Result<String, String> {
    let ext = filename.rsplit('.').next().unwrap_or("").to_lowercase();

    match ext.as_str() {
        "docx" => {
            if is_ole_compound(data) {
                return Err("该文档已加密，暂不支持预览加密的 Office 文档".into());
            }
            extract_docx_text(data).map_err(|e| e.to_string())
        }
        "xlsx" => {
            if is_ole_compound(data) {
                return Err("该文档已加密，暂不支持预览加密的 Office 文档".into());
            }
            extract_xlsx_text(data).map_err(|e| e.to_string())
        }
        "pptx" => {
            if is_ole_compound(data) {
                return Err("该文档已加密，暂不支持预览加密的 Office 文档".into());
            }
            extract_pptx_text(data).map_err(|e| e.to_string())
        }
        "doc" => {
            if is_ole_compound(data) {
                extract_doc_text(data).map_err(|e| e.to_string())
            } else {
                Err(".doc 文件格式无效".into())
            }
        }
        "xls" => {
            if is_ole_compound(data) {
                extract_xls_ole_text(data).map_err(|e| e.to_string())
            } else {
                extract_xlsx_text(data).map_err(|e| e.to_string())
            }
        }
        "csv" => extract_csv_text(data).map_err(|e| e.to_string()),
        _ => Err(format!("不支持的 Office 格式: .{}", ext)),
    }
}



// ───────────────── 格式检测 ─────────────────

/// 检测是否为 OLE 复合文档
fn is_ole_compound(data: &[u8]) -> bool {
    if data.len() < 4 { return false; }
    data[..4] == [0xD0, 0xCF, 0x11, 0xE0]
}

// ───────────────── DOC 提取（旧版 Word OLE） ─────────────────

/// 从 OLE 复合文档中提取 .doc 文本
///
/// 先用 `cfb` crate 解析 OLE 结构，读取 "WordDocument" stream，
/// 再从此 stream 中扫描 UTF-16LE 文本（而非扫描全量文件，大幅降低误报）
fn extract_doc_text(data: &[u8]) -> io::Result<String> {
    use cfb::CompoundFile;

    let cursor = Cursor::new(data);

    // 打开 OLE 复合文档（F: Read + Seek）
    let mut cfb = CompoundFile::open(cursor)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("OLE 解析失败: {}", e)))?;

    // 读取 WordDocument stream（.doc 文件的主文档流，路径以 '/' 开头），限制大小防异常
    let mut stream_data = Vec::new();
    {
        let stream = cfb.open_stream("/WordDocument")
            .map_err(|_| io::Error::new(io::ErrorKind::NotFound,
                "未找到 WordDocument stream（可能不是有效的 .doc 文件）"))?;
        stream.take((MAX_OFFICE_TEXT as u64) + 1).read_to_end(&mut stream_data)?;
    }

    if stream_data.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData,
            "WordDocument stream 为空"));
    }
    if stream_data.len() > MAX_OFFICE_TEXT {
        return Err(io::Error::new(io::ErrorKind::InvalidData,
            "WordDocument stream 超过预览上限"));
    }

    // 从 FIB（File Information Block）之后开始扫描
    // FIB 通常占据前 1024-2048 字节，文本从 offset 0x0400 附近开始
    let scan_start = if stream_data.len() > 0x0800 { 0x0400 } else { 0 };
    let scan_end = stream_data.len() - (stream_data.len() % 2);

    let mut texts = Vec::new();
    let mut current = String::new();

    let mut i = scan_start;
    while i + 1 < scan_end {
        let lo = stream_data[i];
        let hi = stream_data[i + 1];
        let ch = u16::from_le_bytes([lo, hi]);

        // 2.4.1 修复（P2-23）：处理 UTF-16 代理对（CJK 扩展 B 等增补平面字符）。
        // 旧实现把高/低代理分别当独立 u16 转 char，from_u32 失败全部变 '?'。
        if (0xD800..=0xDBFF).contains(&ch) && i + 3 < scan_end {
            let lo2 = stream_data[i + 2];
            let hi2 = stream_data[i + 3];
            let low_pair = u16::from_le_bytes([lo2, hi2]);
            if (0xDC00..=0xDFFF).contains(&low_pair) {
                let c = (((ch as u32) - 0xD800) << 10 | (low_pair as u32) - 0xDC00) + 0x10000;
                current.push(char::from_u32(c).unwrap_or('?'));
                i += 4;
                continue;
            }
        }

        if is_word_text_char(ch) {
            current.push(char::from_u32(ch as u32).unwrap_or('?'));
        } else if current.len() >= 4 {
            let trimmed = current.trim();
            if !trimmed.is_empty() && trimmed.chars().any(|c| c.is_alphabetic()) {
                texts.push(trimmed.to_string());
            }
            current.clear();
        } else {
            current.clear();
        }
        i += 2;
    }

    // 处理最后一段
    if current.len() >= 4 {
        let trimmed = current.trim();
        if !trimmed.is_empty() && trimmed.chars().any(|c| c.is_alphabetic()) {
            texts.push(trimmed.to_string());
        }
    }

    if texts.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData,
            "无法从 .doc 文件中提取文本（可能是加密或格式不支持）"));
    }

    Ok(texts.join("\n"))
}

/// 判断是否为 Word 文本中常见的字符
fn is_word_text_char(ch: u16) -> bool {
    match ch {
        // ASCII 可打印字符
        0x20..=0x7E => true,
        // 中文 CJK 基本区
        0x4E00..=0x9FFF => true,
        // 中文 CJK 扩展 A
        0x3400..=0x4DBF => true,
        // 中文标点
        0x3000..=0x303F => true,
        // 全角 ASCII
        0xFF01..=0xFF5E => true,
        // 日文假名
        0x3040..=0x309F => true,
        0x30A0..=0x30FF => true,
        // 韩文
        0xAC00..=0xD7AF => true,
        // 常见拉丁扩展
        0x00C0..=0x024F => true,
        // Tab / CR / LF
        0x09 | 0x0D | 0x0A => true,
        _ => false,
    }
}

// ───────────────── XLS / XLSX 通用提取 ─────────────────

/// 通用 calamine 工作表提取（消除 Xlsx 和 Xls 的重复逻辑）
fn extract_calamine_sheets<R, RS>(workbook: &mut R) -> io::Result<String>
where
    R: calamine::Reader<RS>,
    RS: std::io::Read + std::io::Seek,
    R::Error: std::fmt::Display,
{
    let mut output = Vec::new();
    let mut total = 0usize;

    let sheet_names = workbook.sheet_names().to_owned();
    // 2.5.1 修复：限制工作表数量（表头行不计入文本总量，需单独设限）
    if sheet_names.len() > MAX_SHEETS {
        return Err(io::Error::new(io::ErrorKind::InvalidData,
            format!("工作表数量过多（{} 个，上限 {}），已拒绝预览", sheet_names.len(), MAX_SHEETS)));
    }

    for sheet_name in sheet_names {
        output.push(format!("── {} ──", sheet_name));

        match workbook.worksheet_range(&sheet_name) {
            Ok(range) => {
                let mut rows_seen = 0usize;
                for row in range.rows() {
                    // 2.5.1 修复：单表行数上限
                    rows_seen += 1;
                    if rows_seen > MAX_ROWS_PER_SHEET {
                        return Err(io::Error::new(io::ErrorKind::InvalidData,
                            format!("工作表 '{}' 行数超过预览上限（{} 行）", sheet_name, MAX_ROWS_PER_SHEET)));
                    }
                    let cells: Vec<String> = row.iter().map(cell_to_string).collect();
                    let line = cells.join("\t");
                    if !line.trim().is_empty() {
                        // 2.3.0 修复：限制预览文本总量，防止超大数据集拖垮内存
                        total += line.len() + 1;
                        if total > MAX_OFFICE_TEXT {
                            return Err(io::Error::new(io::ErrorKind::InvalidData,
                                "表格内容超过预览上限（64 MiB）"));
                        }
                        output.push(line);
                    }
                }
            }
            Err(e) => {
                output.push(format!("[读取错误: {}]", e));
            }
        }
        output.push(String::new());
    }

    Ok(output.join("\n"))
}

/// 从 OLE 复合文档中提取 .xls 文本（旧版 Excel）
fn extract_xls_ole_text(data: &[u8]) -> io::Result<String> {
    use calamine::Xls;
    let cursor = Cursor::new(data);
    let mut workbook: Xls<Cursor<&[u8]>> = Xls::new(cursor)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    extract_calamine_sheets(&mut workbook)
}

// ───────────────── DOCX 提取 ─────────────────

fn extract_docx_text(data: &[u8]) -> io::Result<String> {
    let cursor = Cursor::new(data);
    let mut archive = zip::ZipArchive::new(cursor)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    // 2.5.1 修复：中央目录条目数上限（zip crate 为每个条目分配元数据）
    if archive.len() > MAX_ZIP_ENTRIES {
        return Err(io::Error::new(io::ErrorKind::InvalidData,
            format!("ZIP 条目数量过多（{} 个，上限 {}）", archive.len(), MAX_ZIP_ENTRIES)));
    }

    let xml = read_zip_entry_limited(&mut archive, "word/document.xml")?;
    let xml = String::from_utf8_lossy(&xml);

    parse_docx_xml(&xml)
}

fn parse_docx_xml(xml: &str) -> io::Result<String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();

    let mut paragraphs: Vec<String> = Vec::new();
    let mut current_para = String::new();
    let mut in_para = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                let name = e.name();
                let local = name.as_ref();
                if local == b"w:p" {
                    in_para = true;
                    current_para.clear();
                }
            }
            Ok(Event::Empty(ref e)) => {
                let name = e.name();
                let local = name.as_ref();
                if in_para && (local == b"w:br" || local == b"w:cr") {
                    current_para.push('\n');
                } else if in_para && local == b"w:tab" {
                    current_para.push('\t');
                }
            }
            Ok(Event::Text(ref e)) => {
                if in_para {
                    if let Ok(text) = e.xml10_content() {
                        current_para.push_str(&text);
                    }
                }
            }
            Ok(Event::GeneralRef(ref e)) => {
                if in_para {
                    if let Ok(name) = e.decode() {
                        current_para.push_str(&resolve_general_ref(&name));
                    }
                }
            }
            Ok(Event::End(ref e)) => {
                let name = e.name();
                let local = name.as_ref();
                if local == b"w:p" {
                    let trimmed = current_para.trim();
                    if !trimmed.is_empty() {
                        paragraphs.push(trimmed.to_string());
                    }
                    in_para = false;
                    current_para.clear();
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }

    Ok(paragraphs.join("\n"))
}

// ───────────────── XLSX 提取 ─────────────────

fn extract_xlsx_text(data: &[u8]) -> io::Result<String> {
    use calamine::Xlsx;
    let cursor = Cursor::new(data);
    let mut workbook: Xlsx<Cursor<&[u8]>> = Xlsx::new(cursor)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    extract_calamine_sheets(&mut workbook)
}

fn cell_to_string(cell: &calamine::Data) -> String {
    match cell {
        calamine::Data::Empty => String::new(),
        calamine::Data::String(s) => s.clone(),
        calamine::Data::Float(f) => {
            if f.fract() == 0.0 && f.abs() < i64::MAX as f64 {
                format!("{}", *f as i64)
            } else {
                format!("{}", f)
            }
        }
        calamine::Data::Int(i) => format!("{}", i),
        calamine::Data::Bool(b) => if *b { "TRUE".into() } else { "FALSE".into() },
        calamine::Data::Error(e) => format!("#ERR:{:?}", e),
        calamine::Data::DateTime(d) => format!("{}", d),
        _ => String::new(),
    }
}

// ───────────────── PPTX 提取 ─────────────────

fn extract_pptx_text(data: &[u8]) -> io::Result<String> {
    let cursor = Cursor::new(data);
    let mut archive = zip::ZipArchive::new(cursor)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    // 2.5.1 修复：中央目录条目数上限（与 docx 同策略）
    if archive.len() > MAX_ZIP_ENTRIES {
        return Err(io::Error::new(io::ErrorKind::InvalidData,
            format!("ZIP 条目数量过多（{} 个，上限 {}）", archive.len(), MAX_ZIP_ENTRIES)));
    }

    let mut slides_text = Vec::new();
    let mut total_size = 0usize;

    let file_names: Vec<String> = archive.file_names()
        .filter(|n| n.starts_with("ppt/slides/slide") && n.ends_with(".xml"))
        .map(|n| n.to_string())
        .collect();

    // 2.3.0 修复：限制幻灯片数量，防止恶意 pptx 携带海量幻灯片拖垮内存
    if file_names.len() > 1000 {
        return Err(io::Error::new(io::ErrorKind::InvalidData,
            "幻灯片数量过多（超过 1000 张），已拒绝预览"));
    }

    let mut slide_files = Vec::new();
    for name in &file_names {
        let xml = read_zip_entry_limited(&mut archive, name)?;
        total_size += xml.len();
        if total_size > MAX_OFFICE_TEXT {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                "演示文稿解压总量超过预览上限（可能为压缩炸弹）"));
        }
        slide_files.push(String::from_utf8_lossy(&xml).to_string());
    }

    for (i, xml) in slide_files.iter().enumerate() {
        slides_text.push(format!("── 幻灯片 {} ──", i + 1));
        match parse_pptx_xml(xml) {
            Ok(text) => {
                if text.is_empty() {
                    slides_text.push("[空白幻灯片]".into());
                } else {
                    slides_text.push(text);
                }
            }
            Err(_) => {
                slides_text.push("[解析失败]".into());
            }
        }
        slides_text.push(String::new());
    }

    if slides_text.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "No slides found"));
    }

    Ok(slides_text.join("\n"))
}

fn parse_pptx_xml(xml: &str) -> io::Result<String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();

    let mut texts = Vec::new();
    let mut current_text = String::new();
    let mut in_text = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                let name = e.name();
                let local = name.as_ref();
                if local == b"a:p" {
                    // S5 修复：移除 Start 时的重复 push（End 已处理），仅重置状态
                    current_text.clear();
                    in_text = true;
                }
            }
            Ok(Event::Text(ref e)) => {
                if in_text {
                    if let Ok(t) = e.xml10_content() {
                        current_text.push_str(&t);
                    }
                }
            }
            Ok(Event::GeneralRef(ref e)) => {
                if in_text {
                    if let Ok(name) = e.decode() {
                        current_text.push_str(&resolve_general_ref(&name));
                    }
                }
            }
            Ok(Event::Empty(ref e)) => {
                let name = e.name();
                let local = name.as_ref();
                if in_text && local == b"a:br" {
                    current_text.push('\n');
                }
            }
            Ok(Event::End(ref e)) => {
                let name = e.name();
                let local = name.as_ref();
                if local == b"a:p" {
                    if !current_text.trim().is_empty() {
                        texts.push(current_text.trim().to_string());
                    }
                    current_text.clear();
                    in_text = false;
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }

    if !current_text.trim().is_empty() {
        texts.push(current_text.trim().to_string());
    }

    Ok(texts.join("\n"))
}

// ───────────────── CSV 提取 ─────────────────

fn extract_csv_text(data: &[u8]) -> io::Result<String> {
    // 2.3.0 修复：限制 CSV 预览大小，防止超大文件整串进 UI 拖垮内存
    if data.len() > MAX_OFFICE_TEXT {
        return Err(io::Error::new(io::ErrorKind::InvalidData,
            "CSV 文件超过预览上限（64 MiB），请提取后查看"));
    }
    let text = std::str::from_utf8(data)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8"))?;
    Ok(text.to_string())
}
