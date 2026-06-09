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
use calamine::Reader as CalReader;

// ───────────────── 公共接口 ─────────────────

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

    // 读取 WordDocument stream（.doc 文件的主文档流，路径以 '/' 开头）
    let mut stream_data = Vec::new();
    {
        let mut stream = cfb.open_stream("/WordDocument")
            .map_err(|_| io::Error::new(io::ErrorKind::NotFound,
                "未找到 WordDocument stream（可能不是有效的 .doc 文件）"))?;
        stream.read_to_end(&mut stream_data)?;
    }

    if stream_data.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData,
            "WordDocument stream 为空"));
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

    for sheet_name in workbook.sheet_names().to_owned() {
        output.push(format!("── {} ──", sheet_name));

        match workbook.worksheet_range(&sheet_name) {
            Ok(range) => {
                for row in range.rows() {
                    let cells: Vec<String> = row.iter().map(cell_to_string).collect();
                    let line = cells.join("\t");
                    if !line.trim().is_empty() {
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

    let mut file = archive.by_name("word/document.xml")
        .map_err(|_| io::Error::new(io::ErrorKind::NotFound, "word/document.xml not found"))?;

    let mut xml = String::new();
    file.read_to_string(&mut xml)?;

    parse_docx_xml(&xml)
}

fn parse_docx_xml(xml: &str) -> io::Result<String> {
    let mut reader = Reader::from_str(xml);
    reader.trim_text(true);
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
                    if let Ok(text) = e.unescape() {
                        current_para.push_str(&text);
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

    let mut slides_text = Vec::new();

    let file_names: Vec<String> = archive.file_names()
        .filter(|n| n.starts_with("ppt/slides/slide") && n.ends_with(".xml"))
        .map(|n| n.to_string())
        .collect();

    let mut slide_files = Vec::new();
    for name in &file_names {
        if let Ok(mut f) = archive.by_name(name) {
            let mut xml = String::new();
            if f.read_to_string(&mut xml).is_ok() {
                slide_files.push(xml);
            }
        }
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
    reader.trim_text(true);
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
                    if !current_text.trim().is_empty() {
                        texts.push(current_text.trim().to_string());
                    }
                    current_text.clear();
                    in_text = true;
                }
            }
            Ok(Event::Text(ref e)) => {
                if in_text {
                    if let Ok(t) = e.unescape() {
                        current_text.push_str(&t);
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
    let text = std::str::from_utf8(data)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8"))?;
    Ok(text.to_string())
}
