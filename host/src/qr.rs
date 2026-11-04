//! Renders the FIDO:/ hybrid-transport string as an SVG QR code.

use qrcode::render::svg;
use qrcode::{EcLevel, QrCode};

/// High error correction so the dialog can overlay a small passkey badge in the
/// middle of the code (the way Chrome does) without hurting scannability.
pub fn render_svg(data: &str) -> Result<String, String> {
    let code = QrCode::with_error_correction_level(data.as_bytes(), EcLevel::H)
        .map_err(|e| e.to_string())?;
    Ok(code
        .render::<svg::Color>()
        .min_dimensions(300, 300)
        .quiet_zone(true)
        .dark_color(svg::Color("#000000"))
        .light_color(svg::Color("#ffffff"))
        .build())
}

#[cfg(test)]
mod tests {
    #[test]
    fn renders_fido_string() {
        let svg = super::render_svg("FIDO:/1587255900592798472946741305634621007598415719938516727619448163208289891592241537715212238726862948104002286727120129").unwrap();
        assert!(svg.starts_with("<?xml") || svg.starts_with("<svg"));
        assert!(svg.contains("<svg"));
    }
}
