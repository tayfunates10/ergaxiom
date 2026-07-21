use thiserror::Error;

use crate::model::{DesignLayer, GraphicDesignDocument, PixelRect, Rgba8, TextLayer};

#[derive(Debug, Error)]
pub enum RenderError {
    #[error("canvas dimensions must be positive")]
    InvalidCanvas,
    #[error("layer bounds exceed the canvas")]
    LayerOutsideCanvas,
    #[error("text scale must be positive")]
    InvalidTextScale,
    #[error("pixel buffer size overflow")]
    BufferOverflow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContrastSample {
    pub x: u32,
    pub y: u32,
    pub foreground: Rgba8,
    pub background: Rgba8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedDocument {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u8>,
    pub contrast_samples: Vec<ContrastSample>,
}

pub fn measure_text_bounds(
    copy: &str,
    origin_x: u32,
    origin_y: u32,
    scale: u32,
) -> Result<PixelRect, RenderError> {
    if scale == 0 {
        return Err(RenderError::InvalidTextScale);
    }
    let lines: Vec<_> = copy.split('\n').collect();
    let line_count = u32::try_from(lines.len()).map_err(|_| RenderError::BufferOverflow)?;
    let max_chars = lines
        .iter()
        .map(|line| line.chars().count())
        .max()
        .unwrap_or(0);
    let max_chars = u32::try_from(max_chars).map_err(|_| RenderError::BufferOverflow)?;
    let width = if max_chars == 0 {
        0
    } else {
        max_chars
            .checked_mul(6)
            .and_then(|value| value.checked_sub(1))
            .and_then(|value| value.checked_mul(scale))
            .ok_or(RenderError::BufferOverflow)?
    };
    let height = if line_count == 0 {
        0
    } else {
        line_count
            .checked_mul(8)
            .and_then(|value| value.checked_sub(1))
            .and_then(|value| value.checked_mul(scale))
            .ok_or(RenderError::BufferOverflow)?
    };
    Ok(PixelRect {
        x: origin_x,
        y: origin_y,
        width,
        height,
    })
}

pub fn render_document(document: &GraphicDesignDocument) -> Result<RenderedDocument, RenderError> {
    let width = document.canvas.width;
    let height = document.canvas.height;
    if width == 0 || height == 0 {
        return Err(RenderError::InvalidCanvas);
    }
    let pixel_count = usize::try_from(width)
        .ok()
        .and_then(|value| value.checked_mul(usize::try_from(height).ok()?))
        .and_then(|value| value.checked_mul(4))
        .ok_or(RenderError::BufferOverflow)?;
    let background = document.canvas.background;
    let mut pixels = Vec::with_capacity(pixel_count);
    for _ in 0..u64::from(width) * u64::from(height) {
        pixels.extend_from_slice(&[
            background.red,
            background.green,
            background.blue,
            background.alpha,
        ]);
    }
    let mut samples = Vec::new();

    for layer in &document.layers {
        match layer {
            DesignLayer::Logo(logo) => {
                ensure_rect_inside(logo.bounds, width, height)?;
                for y in logo.bounds.y..logo.bounds.y + logo.bounds.height {
                    for x in logo.bounds.x..logo.bounds.x + logo.bounds.width {
                        let relative_x = x - logo.bounds.x;
                        let relative_y = y - logo.bounds.y;
                        let diagonal = (relative_x / 8 + relative_y / 8) % 2 == 0;
                        let color = if diagonal {
                            logo.primary_color
                        } else {
                            logo.secondary_color
                        };
                        set_pixel(&mut pixels, width, x, y, color)?;
                    }
                }
            }
            DesignLayer::Text(text) => {
                ensure_rect_inside(text.bounds, width, height)?;
                render_text_layer(&mut pixels, width, height, text, &mut samples)?;
            }
        }
    }

    Ok(RenderedDocument {
        width,
        height,
        pixels,
        contrast_samples: samples,
    })
}

pub fn contrast_ratio_milli(foreground: Rgba8, background: Rgba8) -> u32 {
    let foreground_luminance = relative_luminance(foreground);
    let background_luminance = relative_luminance(background);
    let lighter = foreground_luminance.max(background_luminance);
    let darker = foreground_luminance.min(background_luminance);
    (((lighter + 0.05) / (darker + 0.05)) * 1000.0).round() as u32
}

fn render_text_layer(
    pixels: &mut [u8],
    width: u32,
    height: u32,
    text: &TextLayer,
    samples: &mut Vec<ContrastSample>,
) -> Result<(), RenderError> {
    if text.glyph_scale == 0 {
        return Err(RenderError::InvalidTextScale);
    }
    let mut cursor_y = text.origin_y;
    for line in text.approved_copy.split('\n') {
        let mut cursor_x = text.origin_x;
        for character in line.chars() {
            let glyph = glyph_rows(character);
            let mut sampled = false;
            for (row_index, row_bits) in glyph.iter().enumerate() {
                for column in 0..5_u32 {
                    if row_bits & (1 << (4 - column)) == 0 {
                        continue;
                    }
                    for scale_y in 0..text.glyph_scale {
                        for scale_x in 0..text.glyph_scale {
                            let x = cursor_x
                                .checked_add(column * text.glyph_scale)
                                .and_then(|value| value.checked_add(scale_x))
                                .ok_or(RenderError::BufferOverflow)?;
                            let y = cursor_y
                                .checked_add(
                                    u32::try_from(row_index)
                                        .map_err(|_| RenderError::BufferOverflow)?
                                        * text.glyph_scale,
                                )
                                .and_then(|value| value.checked_add(scale_y))
                                .ok_or(RenderError::BufferOverflow)?;
                            if x >= width || y >= height {
                                return Err(RenderError::LayerOutsideCanvas);
                            }
                            let background = get_pixel(pixels, width, x, y)?;
                            if !sampled {
                                samples.push(ContrastSample {
                                    x,
                                    y,
                                    foreground: text.color,
                                    background,
                                });
                                sampled = true;
                            }
                            set_pixel(pixels, width, x, y, text.color)?;
                        }
                    }
                }
            }
            cursor_x = cursor_x
                .checked_add(6 * text.glyph_scale)
                .ok_or(RenderError::BufferOverflow)?;
        }
        cursor_y = cursor_y
            .checked_add(8 * text.glyph_scale)
            .ok_or(RenderError::BufferOverflow)?;
    }
    Ok(())
}

fn ensure_rect_inside(rect: PixelRect, width: u32, height: u32) -> Result<(), RenderError> {
    if rect
        .x
        .checked_add(rect.width)
        .is_none_or(|right| right > width)
        || rect
            .y
            .checked_add(rect.height)
            .is_none_or(|bottom| bottom > height)
    {
        Err(RenderError::LayerOutsideCanvas)
    } else {
        Ok(())
    }
}

fn pixel_offset(width: u32, x: u32, y: u32) -> Result<usize, RenderError> {
    usize::try_from(y)
        .ok()
        .and_then(|row| row.checked_mul(usize::try_from(width).ok()?))
        .and_then(|value| value.checked_add(usize::try_from(x).ok()?))
        .and_then(|value| value.checked_mul(4))
        .ok_or(RenderError::BufferOverflow)
}

fn get_pixel(pixels: &[u8], width: u32, x: u32, y: u32) -> Result<Rgba8, RenderError> {
    let offset = pixel_offset(width, x, y)?;
    let pixel = pixels
        .get(offset..offset + 4)
        .ok_or(RenderError::BufferOverflow)?;
    Ok(Rgba8 {
        red: pixel[0],
        green: pixel[1],
        blue: pixel[2],
        alpha: pixel[3],
    })
}

fn set_pixel(
    pixels: &mut [u8],
    width: u32,
    x: u32,
    y: u32,
    color: Rgba8,
) -> Result<(), RenderError> {
    let offset = pixel_offset(width, x, y)?;
    let pixel = pixels
        .get_mut(offset..offset + 4)
        .ok_or(RenderError::BufferOverflow)?;
    pixel.copy_from_slice(&[color.red, color.green, color.blue, color.alpha]);
    Ok(())
}

fn relative_luminance(color: Rgba8) -> f64 {
    fn linear(channel: u8) -> f64 {
        let value = f64::from(channel) / 255.0;
        if value <= 0.04045 {
            value / 12.92
        } else {
            ((value + 0.055) / 1.055).powf(2.4)
        }
    }
    0.2126 * linear(color.red) + 0.7152 * linear(color.green) + 0.0722 * linear(color.blue)
}

fn glyph_rows(character: char) -> [u8; 7] {
    match character.to_ascii_uppercase() {
        'A' => [
            0b01110, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001,
        ],
        'B' => [
            0b11110, 0b10001, 0b10001, 0b11110, 0b10001, 0b10001, 0b11110,
        ],
        'C' => [
            0b01111, 0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b01111,
        ],
        'D' => [
            0b11110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b11110,
        ],
        'E' => [
            0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b11111,
        ],
        'F' => [
            0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b10000,
        ],
        'G' => [
            0b01111, 0b10000, 0b10000, 0b10111, 0b10001, 0b10001, 0b01111,
        ],
        'H' => [
            0b10001, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001,
        ],
        'I' => [
            0b11111, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b11111,
        ],
        'J' => [
            0b00111, 0b00010, 0b00010, 0b00010, 0b10010, 0b10010, 0b01100,
        ],
        'K' => [
            0b10001, 0b10010, 0b10100, 0b11000, 0b10100, 0b10010, 0b10001,
        ],
        'L' => [
            0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b11111,
        ],
        'M' => [
            0b10001, 0b11011, 0b10101, 0b10101, 0b10001, 0b10001, 0b10001,
        ],
        'N' => [
            0b10001, 0b11001, 0b10101, 0b10011, 0b10001, 0b10001, 0b10001,
        ],
        'O' => [
            0b01110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110,
        ],
        'P' => [
            0b11110, 0b10001, 0b10001, 0b11110, 0b10000, 0b10000, 0b10000,
        ],
        'Q' => [
            0b01110, 0b10001, 0b10001, 0b10001, 0b10101, 0b10010, 0b01101,
        ],
        'R' => [
            0b11110, 0b10001, 0b10001, 0b11110, 0b10100, 0b10010, 0b10001,
        ],
        'S' => [
            0b01111, 0b10000, 0b10000, 0b01110, 0b00001, 0b00001, 0b11110,
        ],
        'T' => [
            0b11111, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100,
        ],
        'U' => [
            0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110,
        ],
        'V' => [
            0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01010, 0b00100,
        ],
        'W' => [
            0b10001, 0b10001, 0b10001, 0b10101, 0b10101, 0b10101, 0b01010,
        ],
        'X' => [
            0b10001, 0b10001, 0b01010, 0b00100, 0b01010, 0b10001, 0b10001,
        ],
        'Y' => [
            0b10001, 0b10001, 0b01010, 0b00100, 0b00100, 0b00100, 0b00100,
        ],
        'Z' => [
            0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b10000, 0b11111,
        ],
        '0' => [
            0b01110, 0b10001, 0b10011, 0b10101, 0b11001, 0b10001, 0b01110,
        ],
        '1' => [
            0b00100, 0b01100, 0b00100, 0b00100, 0b00100, 0b00100, 0b01110,
        ],
        '2' => [
            0b01110, 0b10001, 0b00001, 0b00010, 0b00100, 0b01000, 0b11111,
        ],
        '3' => [
            0b11110, 0b00001, 0b00001, 0b01110, 0b00001, 0b00001, 0b11110,
        ],
        '4' => [
            0b00010, 0b00110, 0b01010, 0b10010, 0b11111, 0b00010, 0b00010,
        ],
        '5' => [
            0b11111, 0b10000, 0b10000, 0b11110, 0b00001, 0b00001, 0b11110,
        ],
        '6' => [
            0b01110, 0b10000, 0b10000, 0b11110, 0b10001, 0b10001, 0b01110,
        ],
        '7' => [
            0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b01000, 0b01000,
        ],
        '8' => [
            0b01110, 0b10001, 0b10001, 0b01110, 0b10001, 0b10001, 0b01110,
        ],
        '9' => [
            0b01110, 0b10001, 0b10001, 0b01111, 0b00001, 0b00001, 0b01110,
        ],
        ' ' => [0, 0, 0, 0, 0, 0, 0],
        '-' => [0, 0, 0, 0b11111, 0, 0, 0],
        '.' => [0, 0, 0, 0, 0, 0b00110, 0b00110],
        ':' => [0, 0b00110, 0b00110, 0, 0b00110, 0b00110, 0],
        _ => [
            0b11111, 0b10001, 0b00110, 0b00100, 0b00110, 0b10001, 0b11111,
        ],
    }
}
