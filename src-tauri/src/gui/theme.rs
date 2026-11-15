//! 备用 GUI 视觉主题 —— 对齐主界面 `ui/styles.css`（theme-blue）。
//!
//! egui 默认是深色桌面控件风格，与原版的浅色玻璃拟态差距很大。这里集中
//! 定义调色板、控件视觉、字体、渐变背景与自定义行/按钮绘制，界面代码只
//! 引用语义化颜色，保证两个前端观感一致。

use egui::{
    Align2, Color32, CursorIcon, FontId, Frame, Margin, Rect, Response, Rounding, Sense, Shadow,
    Stroke, TextStyle, Ui, UiBuilder, Vec2, ViewportCommand,
};

// ───────────────── 调色板（theme-blue）─────────────────

/// 正文墨色
pub const INK: Color32 = Color32::from_rgb(0x17, 0x23, 0x33);
/// 按钮文字
pub const INK_SOFT: Color32 = Color32::from_rgb(0x28, 0x42, 0x58);
/// 次要文字
pub const MUTED: Color32 = Color32::from_rgb(0x65, 0x75, 0x89);
/// 更淡的说明文字
pub const MUTED_LIGHT: Color32 = Color32::from_rgb(0x7b, 0x8c, 0x9d);
/// 品牌字色
pub const BRAND: Color32 = Color32::from_rgb(0x31, 0x54, 0x6a);
/// 链接色
pub const LINK: Color32 = Color32::from_rgb(0x4a, 0x7d, 0x99);
/// 悬停时的强调文字
pub const LINK_DARK: Color32 = Color32::from_rgb(0x12, 0x6d, 0x95);
/// 主按钮渐变起点（青）
pub const ACCENT_A: Color32 = Color32::from_rgb(0x0b, 0x9e, 0xac);
/// 主按钮渐变终点（蓝）
pub const ACCENT_B: Color32 = Color32::from_rgb(0x24, 0x74, 0xd5);
/// 危险操作
pub const DANGER: Color32 = Color32::from_rgb(0xc7, 0x3f, 0x5b);
/// 成功提示
pub const SUCCESS: Color32 = Color32::from_rgb(0x1f, 0x9d, 0x6b);
/// 警告提示
pub const WARNING: Color32 = Color32::from_rgb(0x8a, 0x6d, 0x1a);

// 渐变背景（135° 三段）
const GRAD_A: Color32 = Color32::from_rgb(0xd9, 0xf4, 0xf1);
const GRAD_B: Color32 = Color32::from_rgb(0xe8, 0xf2, 0xff);
const GRAD_C: Color32 = Color32::from_rgb(0xf8, 0xea, 0xfb);
/// 窗口清屏色（渐变覆盖不到时的兜底色，避免透明窗口出现黑边）
pub const BASE: Color32 = Color32::from_rgb(0xe9, 0xf3, 0xfb);

// 玻璃面板
pub const SURFACE: Color32 = Color32::from_rgba_premultiplied(199, 199, 199, 199); // 白 78%
pub const SURFACE_STRONG: Color32 = Color32::from_rgba_premultiplied(235, 235, 235, 235);
pub const TITLEBAR_BG: Color32 = Color32::from_rgba_premultiplied(107, 107, 107, 107); // 白 42%
pub const TOOLBAR_BG: Color32 = Color32::from_rgba_premultiplied(133, 133, 133, 133); // 白 52%
pub const NAV_BG: Color32 = Color32::from_rgba_premultiplied(107, 107, 107, 107);
pub const INPUT_BG: Color32 = Color32::from_rgba_premultiplied(194, 194, 194, 194); // 白 76%
pub const BTN_BG: Color32 = Color32::from_rgba_premultiplied(184, 184, 184, 184); // 白 72%
pub const BTN_HOVER_BG: Color32 = Color32::from_rgba_premultiplied(235, 235, 235, 235);
/// 行悬停底色（青 14%）
pub const ROW_HOVER: Color32 = Color32::from_rgba_premultiplied(12, 26, 30, 36);
/// 选中行渐变两端（青 20% → 蓝 18%）
pub const ROW_SEL_A: Color32 = Color32::from_rgba_premultiplied(7, 36, 36, 51);
pub const ROW_SEL_B: Color32 = Color32::from_rgba_premultiplied(14, 23, 40, 46);
/// 窗口控制按钮悬停底
pub const WC_HOVER: Color32 = Color32::from_rgba_premultiplied(9, 16, 21, 33);
/// 分隔线
pub const SEP: Color32 = Color32::from_rgba_premultiplied(17, 26, 33, 60);
/// 卡片描边
pub const CARD_STROKE: Color32 = Color32::from_rgba_premultiplied(20, 26, 31, 44);

// ───────────────── 样式安装 ─────────────────

pub fn apply(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();

    style.spacing.item_spacing = Vec2::new(8.0, 8.0);
    style.spacing.button_padding = Vec2::new(12.0, 5.0);
    style.spacing.interact_size = Vec2::new(32.0, 26.0);
    style.spacing.window_margin = Margin::same(18.0);
    style.spacing.menu_margin = Margin::same(5.0);
    style.spacing.indent = 16.0;

    style.text_styles = [
        (TextStyle::Heading, FontId::proportional(15.0)),
        (TextStyle::Body, FontId::proportional(13.0)),
        (TextStyle::Button, FontId::proportional(12.0)),
        (TextStyle::Small, FontId::proportional(11.0)),
        (TextStyle::Monospace, FontId::monospace(12.0)),
    ]
    .into();

    let v = &mut style.visuals;
    v.dark_mode = false;
    v.override_text_color = Some(INK);
    v.panel_fill = BASE;
    v.window_fill = SURFACE_STRONG;
    v.window_stroke = Stroke::new(1.0, CARD_STROKE);
    v.window_rounding = Rounding::same(15.0);
    v.window_shadow = Shadow {
        offset: Vec2::new(0.0, 14.0),
        blur: 34.0,
        spread: 0.0,
        color: Color32::from_rgba_premultiplied(10, 25, 39, 70),
    };
    v.popup_shadow = v.window_shadow;
    v.menu_rounding = Rounding::same(10.0);
    v.extreme_bg_color = INPUT_BG;
    v.faint_bg_color = Color32::from_rgba_premultiplied(188, 193, 196, 200);
    v.hyperlink_color = LINK;
    v.selection.bg_fill = Color32::from_rgba_premultiplied(7, 36, 36, 60);
    v.selection.stroke = Stroke::new(1.0, ACCENT_A);

    let w = &mut v.widgets;
    w.noninteractive = widget(Color32::TRANSPARENT, INK, Stroke::new(1.0, SEP));
    w.inactive = widget(BTN_BG, INK_SOFT, Stroke::NONE);
    w.hovered = widget(BTN_HOVER_BG, LINK_DARK, Stroke::NONE);
    w.active = widget(Color32::WHITE, LINK_DARK, Stroke::NONE);
    w.open = widget(Color32::WHITE, LINK_DARK, Stroke::NONE);

    ctx.set_style(style);
}

fn widget(bg: Color32, fg: Color32, stroke: Stroke) -> egui::style::WidgetVisuals {
    egui::style::WidgetVisuals {
        bg_fill: bg,
        weak_bg_fill: bg,
        bg_stroke: stroke,
        rounding: Rounding::same(8.0),
        fg_stroke: Stroke::new(1.0, fg),
        expansion: 0.0,
    }
}

// ───────────────── 背景与容器 ─────────────────

/// 全窗口 135° 渐变背景（画在 Background 层，位于所有面板之下）
pub fn paint_background(ctx: &egui::Context) {
    let rect = ctx.screen_rect();
    let painter = ctx.layer_painter(egui::LayerId::background());
    paint_gradient(&painter, rect, GRAD_A, GRAD_B, GRAD_B, GRAD_C);
}

/// 四角插值的线性渐变（两个三角形即可）
pub fn paint_gradient(
    painter: &egui::Painter,
    rect: Rect,
    tl: Color32,
    tr: Color32,
    bl: Color32,
    br: Color32,
) {
    let uv = egui::epaint::WHITE_UV;
    let mut mesh = egui::Mesh::default();
    mesh.vertices.push(egui::epaint::Vertex {
        pos: rect.left_top(),
        uv,
        color: tl,
    });
    mesh.vertices.push(egui::epaint::Vertex {
        pos: rect.right_top(),
        uv,
        color: tr,
    });
    mesh.vertices.push(egui::epaint::Vertex {
        pos: rect.left_bottom(),
        uv,
        color: bl,
    });
    mesh.vertices.push(egui::epaint::Vertex {
        pos: rect.right_bottom(),
        uv,
        color: br,
    });
    mesh.add_triangle(0, 1, 2);
    mesh.add_triangle(2, 1, 3);
    painter.add(egui::Shape::mesh(mesh));
}

/// 文件列表卡片（圆角白面 + 细描边，对应 #file-list）
pub fn list_frame() -> Frame {
    Frame::none()
        .fill(SURFACE)
        .rounding(Rounding::same(12.0))
        .stroke(Stroke::new(1.0, CARD_STROKE))
        .inner_margin(Margin::symmetric(5.0, 5.0))
}

/// 居中卡片容器（启动检测 / 解锁页）：先画卡片，再把内容放进卡片内边距
pub fn centered_card(ui: &mut Ui, width: f32, height: f32, add: impl FnOnce(&mut Ui)) {
    let avail = ui.available_rect_before_wrap();
    let w = width.min((avail.width() - 40.0).max(280.0));
    let h = height.min((avail.height() - 40.0).max(220.0));
    let rect = Rect::from_center_size(avail.center(), Vec2::new(w, h));
    let painter = ui.painter();
    painter.rect_filled(rect, Rounding::same(16.0), SURFACE_STRONG);
    painter.rect_stroke(rect, Rounding::same(16.0), Stroke::new(1.0, CARD_STROKE));
    let inner = rect.shrink(22.0);
    ui.scope_builder(UiBuilder::new().max_rect(inner), add);
}

// ───────────────── 自定义控件 ─────────────────

/// 主按钮（渐变强调色实心底 + 白字，近似 CSS 的 linear-gradient）
pub fn primary_button(ui: &mut Ui, text: &str, enabled: bool) -> Response {
    let font = FontId::proportional(12.0);
    let galley = ui
        .painter()
        .layout_no_wrap(text.to_owned(), font, Color32::WHITE);
    let size = Vec2::new(
        (galley.size().x + 28.0).max(88.0),
        (galley.size().y + 14.0).max(30.0),
    );
    let sense = if enabled {
        Sense::click()
    } else {
        Sense::hover()
    };
    let (rect, resp) = ui.allocate_exact_size(size, sense);
    let hovered = enabled && resp.hovered();
    let painter = ui.painter();
    if enabled {
        // 轻投影 + 渐变底（用 8 条竖带近似渐变）
        painter.rect_filled(
            rect,
            Rounding::same(8.0),
            Color32::from_rgba_premultiplied(2, 8, 12, 40),
        );
        painter.rect_filled(
            rect,
            Rounding::same(8.0),
            lerp_color(ACCENT_A, ACCENT_B, 0.5),
        );
        if hovered {
            painter.rect_filled(
                rect,
                Rounding::same(8.0),
                Color32::from_rgba_premultiplied(26, 26, 26, 26),
            );
        }
    } else {
        painter.rect_filled(
            rect,
            Rounding::same(8.0),
            Color32::from_rgba_premultiplied(60, 60, 60, 90),
        );
    }
    let fg = if enabled { Color32::WHITE } else { MUTED_LIGHT };
    painter.galley(rect.center() - galley.size() / 2.0, galley, fg);
    resp
}

/// 标题栏窗口控制按钮（− □ ×）
pub fn window_control(ui: &mut Ui, glyph: &str, close: bool) -> Response {
    let size = Vec2::new(42.0, 36.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
    let painter = ui.painter();
    if resp.hovered() {
        let bg = if close {
            Color32::from_rgb(0xd9, 0x4c, 0x62)
        } else {
            WC_HOVER
        };
        painter.rect_filled(rect, Rounding::ZERO, bg);
    }
    let fg = if resp.hovered() && close {
        Color32::WHITE
    } else {
        Color32::from_rgb(0x49, 0x61, 0x74)
    };
    let size_px = if close { 18.0 } else { 14.0 };
    painter.text(
        rect.center(),
        Align2::CENTER_CENTER,
        glyph,
        FontId::proportional(size_px),
        fg,
    );
    resp
}

/// 工具栏分组竖线（对应 #toolbar .sep）
pub fn toolbar_sep(ui: &mut Ui) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(11.0, 24.0), Sense::hover());
    ui.painter().line_segment(
        [
            egui::pos2(rect.center().x, rect.top() + 3.0),
            egui::pos2(rect.center().x, rect.bottom() - 3.0),
        ],
        Stroke::new(1.0, SEP),
    );
}

/// 文件行（对应 .file-item）：图标 + 名称 + 右对齐大小，悬停/选中高亮
pub fn file_row(
    ui: &mut Ui,
    icon: &str,
    name: &str,
    size: Option<&str>,
    selected: bool,
) -> Response {
    let height = 30.0;
    let width = ui.available_width();
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(width, height), Sense::click());
    let painter = ui.painter();
    if selected {
        paint_gradient(painter, rect, ROW_SEL_A, ROW_SEL_B, ROW_SEL_A, ROW_SEL_B);
        painter.rect_filled(rect, Rounding::same(8.0), Color32::TRANSPARENT);
    } else if resp.hovered() {
        painter.rect_filled(rect, Rounding::same(8.0), ROW_HOVER);
    }

    let icon_pos = egui::pos2(rect.left() + 18.0, rect.center().y);
    painter.text(
        icon_pos,
        Align2::CENTER_CENTER,
        icon,
        FontId::proportional(15.0),
        INK_SOFT,
    );

    let name_left = rect.left() + 34.0;
    let size_w = 86.0;
    let name_area = Rect::from_min_max(
        egui::pos2(name_left, rect.top()),
        egui::pos2(rect.right() - size_w - 10.0, rect.bottom()),
    );
    let galley = ellipsis(ui, name, 13.0, name_area.width().max(20.0));
    let name_y = rect.center().y - galley.size().y / 2.0 - 2.0;
    painter
        .with_clip_rect(name_area)
        .galley(egui::pos2(name_left, name_y), galley, INK);

    if let Some(sz) = size {
        painter.text(
            egui::pos2(rect.right() - 12.0, rect.center().y),
            Align2::RIGHT_CENTER,
            sz,
            FontId::proportional(12.0),
            MUTED,
        );
    }
    resp
}

/// 启动检测列表项（对应 .sd-item）：图标 + 名称 + 时间/大小，悬停高亮
pub fn vault_row(ui: &mut Ui, name: &str, meta: &str) -> Response {
    let height = 46.0;
    let width = ui.available_width();
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(width, height), Sense::click());
    let painter = ui.painter();
    if resp.hovered() {
        paint_gradient(painter, rect, ROW_SEL_A, ROW_SEL_B, ROW_SEL_A, ROW_SEL_B);
        painter.rect_filled(rect, Rounding::same(10.0), Color32::TRANSPARENT);
    } else {
        painter.rect_filled(
            rect,
            Rounding::same(10.0),
            Color32::from_rgba_premultiplied(212, 216, 219, 219),
        );
    }
    painter.text(
        egui::pos2(rect.left() + 20.0, rect.center().y),
        Align2::CENTER_CENTER,
        "🔐",
        FontId::proportional(18.0),
        INK_SOFT,
    );
    let text_left = rect.left() + 38.0;
    painter.text(
        egui::pos2(text_left, rect.top() + 14.0),
        Align2::LEFT_TOP,
        name,
        FontId::proportional(13.0),
        INK,
    );
    painter.text(
        egui::pos2(text_left, rect.top() + 28.0),
        Align2::LEFT_TOP,
        meta,
        FontId::proportional(11.0),
        MUTED_LIGHT,
    );
    resp
}

/// 按可用宽度截断文本并补「…」
pub fn ellipsis(ui: &Ui, text: &str, size: f32, max_width: f32) -> std::sync::Arc<egui::Galley> {
    let font = FontId::proportional(size);
    let full = ui
        .painter()
        .layout_no_wrap(text.to_owned(), font.clone(), INK);
    if full.size().x <= max_width {
        return full;
    }
    let mut chars: Vec<char> = text.chars().collect();
    while !chars.is_empty() {
        chars.pop();
        let candidate: String = chars.iter().collect::<String>() + "…";
        let g = ui.painter().layout_no_wrap(candidate, font.clone(), INK);
        if g.size().x <= max_width {
            return g;
        }
    }
    ui.painter().layout_no_wrap("…".to_owned(), font, INK)
}

/// 按扩展名/文件夹取图标（与 app.js getIcon 同一张表）
pub fn file_icon(name: &str, is_folder: bool) -> &'static str {
    if is_folder {
        return "📁";
    }
    let ext = name
        .rsplit('.')
        .next()
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "png" | "jpg" | "jpeg" | "gif" | "bmp" | "webp" | "tiff" | "tif" => "🖼️",
        "mp4" | "mkv" | "avi" | "mov" | "webm" => "🎬",
        "mp3" | "wav" | "flac" | "aac" | "ogg" | "m4a" => "🎵",
        "zip" | "rar" | "7z" | "tar" | "gz" => "📦",
        "txt" | "md" | "log" => "📄",
        "doc" | "docx" => "📝",
        "xls" | "xlsx" | "csv" => "📊",
        "pdf" => "📕",
        "html" | "htm" | "css" => "🌐",
        "js" | "ts" | "json" | "rs" | "py" | "go" | "c" | "cpp" | "h" | "java" | "sh" | "bat"
        | "ps1" | "toml" | "yaml" | "yml" | "xml" | "ini" => "⚙️",
        "lyt" | "vault" => "🔐",
        _ => "📄",
    }
}

fn lerp_color(a: Color32, b: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    let f = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t).round() as u8;
    Color32::from_rgb(f(a.r(), b.r()), f(a.g(), b.g()), f(a.b(), b.b()))
}

// ───────────────── 无边框窗口的拖拽 / 缩放 ─────────────────

/// 指针贴近窗口边缘时切换缩放光标，按下即请求系统开始缩放。
/// （无边框窗口没有系统提供的缩放边框，需要自行实现。）
pub fn handle_edge_resize(ctx: &egui::Context) {
    let maximized = ctx.input(|i| i.viewport().maximized).unwrap_or(false);
    if maximized {
        return;
    }
    let Some(pos) = ctx.input(|i| i.pointer.hover_pos()) else {
        return;
    };
    let rect = ctx.screen_rect();
    const M: f32 = 5.0;
    let left = pos.x <= rect.left() + M;
    let right = pos.x >= rect.right() - M;
    let top = pos.y <= rect.top() + M;
    let bottom = pos.y >= rect.bottom() - M;
    let dir = match (left, right, top, bottom) {
        (true, _, true, _) => Some((
            egui::viewport::ResizeDirection::NorthWest,
            CursorIcon::ResizeNwSe,
        )),
        (_, true, true, _) => Some((
            egui::viewport::ResizeDirection::NorthEast,
            CursorIcon::ResizeNeSw,
        )),
        (true, _, _, true) => Some((
            egui::viewport::ResizeDirection::SouthWest,
            CursorIcon::ResizeNeSw,
        )),
        (_, true, _, true) => Some((
            egui::viewport::ResizeDirection::SouthEast,
            CursorIcon::ResizeNwSe,
        )),
        (true, _, _, _) => Some((
            egui::viewport::ResizeDirection::West,
            CursorIcon::ResizeHorizontal,
        )),
        (_, true, _, _) => Some((
            egui::viewport::ResizeDirection::East,
            CursorIcon::ResizeHorizontal,
        )),
        (_, _, true, _) => Some((
            egui::viewport::ResizeDirection::North,
            CursorIcon::ResizeVertical,
        )),
        (_, _, _, true) => Some((
            egui::viewport::ResizeDirection::South,
            CursorIcon::ResizeVertical,
        )),
        _ => None,
    };
    if let Some((dir, icon)) = dir {
        ctx.set_cursor_icon(icon);
        if ctx.input(|i| i.pointer.any_pressed()) {
            ctx.send_viewport_cmd(ViewportCommand::BeginResize(dir));
        }
    }
}
