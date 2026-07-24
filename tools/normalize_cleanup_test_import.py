from pathlib import Path

path = Path("crates/background-cleanup-certified-path-runtime/tests/real_certificate.rs")
text = path.read_text(encoding="utf-8")
old = """    compile_background_cleanup_intent, encode_restricted_srgb_rgba_png, execute_background_cleanup,
    execute_inkscape_cleanup_probe, synthesize_background_cleanup_plan,
    validate_background_cleanup,
"""
new = """    compile_background_cleanup_intent, encode_restricted_srgb_rgba_png,
    execute_background_cleanup, execute_inkscape_cleanup_probe,
    synthesize_background_cleanup_plan, validate_background_cleanup,
"""
if old not in text:
    raise SystemExit("current rustfmt import block is missing")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
