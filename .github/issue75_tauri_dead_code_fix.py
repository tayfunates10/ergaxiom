from pathlib import Path

commands = Path("apps/desktop/src-tauri/src/commands.rs")
text = commands.read_text()
needle = "    pub fn approve(\n        &self,\n        request: DesktopApprovalRequest,\n"
replacement = "    #[cfg(test)]\n    pub fn approve(\n        &self,\n        request: DesktopApprovalRequest,\n"
if text.count(needle) != 1:
    raise SystemExit(f"commands approve pattern count={text.count(needle)}")
commands.write_text(text.replace(needle, replacement, 1))

pipeline = Path("apps/desktop/src-tauri/src/pipeline.rs")
text = pipeline.read_text()
replacements = [
    ("    Executed(&'a DesktopApprovalRecord),\n", ""),
    ("    RolledBack(&'a DesktopApprovalRecord),\n", ""),
    ("            Self::Executed(_) => DesktopControlStatus::Executed,\n", ""),
    ("            Self::RolledBack(_) => DesktopControlStatus::RolledBack,\n", ""),
    (
        "            Self::Approved(record) | Self::Executed(record) | Self::RolledBack(record) => {\n                Some(record)\n            }\n",
        "            Self::Approved(record) => Some(record),\n",
    ),
    (
        "            Self::Approved(_) | Self::Executed(_) | Self::RolledBack(_) => StageStatus::Passed,\n",
        "            Self::Approved(_) => StageStatus::Passed,\n",
    ),
    (
        "            Self::Cancelled(_) | Self::RolledBack(_) => StageStatus::Blocked,\n",
        "            Self::Cancelled(_) => StageStatus::Blocked,\n",
    ),
    (
        "    if matches!(mode, PipelineSnapshotMode::Executed(_)) {\n        return Err(\n            \"production execution cannot be synthesized by the prepare-only desktop pipeline\"\n                .to_owned(),\n        );\n    }\n",
        "",
    ),
    (
        "        assert!(build_pipeline_snapshot(PipelineSnapshotMode::Executed(&approval)).is_err());\n",
        "",
    ),
]
for old, new in replacements:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"pipeline pattern count={count}: {old!r}")
    text = text.replace(old, new, 1)
pipeline.write_text(text)
