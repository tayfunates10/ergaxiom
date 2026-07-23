# Independent Rendered Contrast Validator

The rendered contrast validator consumes independently decoded RGBA pixels. It does not trust SVG declarations, Inkscape object properties or exporter success as proof of visible contrast.

## Measurement model

A policy declares a text-specific subject rectangle and a local background-ring thickness. The ring is the expanded rectangle minus the subject rectangle, so the sampled background remains immediately adjacent to the rendered text region.

The validator requires the subject rectangle and its complete ring to remain inside the decoded image. Both regions must be opaque in version 1.

## Background measurement

The local background color is calculated independently per RGB channel using 256-bin histograms and a deterministic median. Every ring pixel is then compared with that median. A policy-defined maximum channel deviation limits gradients, patterns or unexpected objects around the subject. A nonuniform ring is an explicit blocker.

## Core foreground measurement

Pixels inside the subject rectangle become foreground candidates only when their squared RGB distance from the measured background exceeds the declared threshold. Candidate coverage is bounded so that an incorrect rectangle containing a large unrelated object cannot silently pass.

Candidate colors are quantized into deterministic RGB bins. The dominant bin represents core letter pixels; anti-aliased edge pixels normally fall into neighboring bins. Acceptance requires minimum candidate count, minimum dominant count and minimum dominant share.

The representative foreground color is the per-channel median of the dominant bin. The validator also computes the contrast of every dominant-bin pixel and reports the minimum, preventing a high-contrast average from hiding weaker core pixels.

## Contrast calculation

WCAG 2.2 sRGB relative luminance is implemented as an immutable 256-entry fixed-point lookup table. No runtime floating-point exponentiation participates in the decision.

For luminances scaled to one million, contrast is calculated as:

`(lighter + 0.05) / (darker + 0.05)`

and reported in thousandths. A minimum policy value of `4500` therefore represents 4.5:1.

## Evidence report

The deterministic report binds:

- PNG artifact digest,
- pixel-decoder report and RGBA digests,
- subject and background-ring geometry,
- opaque and sampled pixel counts,
- measured background RGB and maximum deviation,
- candidate count and coverage,
- dominant color bin, count and share,
- foreground RGB,
- fixed-point foreground and background luminance,
- representative contrast,
- minimum dominant-pixel contrast, and
- canonical report and decision digests.

## Real Inkscape acceptance test

The permanent Inkscape workflow exports the controlled fixture, performs proof-bound sRGB normalization, independently decodes the normalized PNG and measures the rendered headline. Acceptance requires the real core text pixels to exceed the contract-style 4.5:1 threshold against a uniform local panel background.

## Claim boundary

Version 1 validates contrast for a declared text-specific rendered region. It does not discover text automatically, perform OCR, prove approved-copy identity, identify logo geometry or infer safe areas. Those claims require separate validators whose independently derived regions or masks can then be supplied to this pixel-level measurement layer.
