use qrcode::{Color, EcLevel, QrCode};

pub struct RenderedQr {
    pub text: String,
    pub line_count: usize,
}

/// Renders `url` as a compact UTF-8 half-block QR code with a 2-module white quiet zone
/// and explicit black-on-white ANSI colors (`\x1b[47;30m`) for reliable camera scanning
/// on both dark and light terminal themes.
pub fn render_terminal_qr(url: &str) -> Result<RenderedQr, qrcode::types::QrError> {
    let code = QrCode::with_error_correction_level(url.as_bytes(), EcLevel::L)?;
    let width = code.width();
    let quiet: isize = 2;
    let total = (width as isize) + quiet * 2;

    let is_dark = |x: isize, y: isize| -> bool {
        let mx = x - quiet;
        let my = y - quiet;
        if mx < 0 || my < 0 || mx >= width as isize || my >= width as isize {
            false
        } else {
            code[(mx as usize, my as usize)] == Color::Dark
        }
    };

    let mut out = String::new();
    let mut line_count = 0usize;

    let mut y = 0isize;
    while y < total {
        out.push_str("\x1b[47;30m");
        for x in 0..total {
            let top = is_dark(x, y);
            let bot = if y + 1 < total {
                is_dark(x, y + 1)
            } else {
                false
            };
            let ch = match (top, bot) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            };
            out.push(ch);
        }
        out.push_str("\x1b[0m\n");
        line_count += 1;
        y += 2;
    }

    Ok(RenderedQr {
        text: out,
        line_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_high_contrast_half_block_qr_with_accurate_line_count() {
        let rendered = render_terminal_qr("https://box.tailnet.ts.net:8443/auth/abc123").unwrap();
        assert!(!rendered.text.is_empty());
        assert_eq!(rendered.text.lines().count(), rendered.line_count);
        assert!(rendered.text.contains("\x1b[47;30m"));
        assert!(rendered.text.contains("\x1b[0m"));
        assert!(rendered.text.contains('█') || rendered.text.contains('▀') || rendered.text.contains('▄'));
    }
}
