from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CAPSULE_PATH = ROOT / "professions/graphic-designer/profession.json"
CAPSULE_VERSION = "0.6.0"
JOB_ID = "print_ready_poster_preflight"
OPERATORS = [
    "print.validate_source",
    "print.export_pdf_with_inkscape",
    "print.certify_preflight",
]
CONSTRAINTS = [
    "restricted_svg_profile",
    "canvas_dimensions_match",
    "bleed_coverage",
    "safe_area_satisfied",
    "palette_violations",
    "vector_only",
    "fonts_outlined",
    "page_count",
    "media_box_match",
    "trim_box_match",
    "bleed_box_match",
    "crop_box_match",
    "pdf_version",
    "allowed_color_spaces",
    "transparency_absent",
    "external_actions_absent",
    "source_immutable",
    "inkscape_export_verified",
]


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def replace_by_id(items: list[dict], item: dict) -> None:
    items[:] = [existing for existing in items if existing.get("id") != item["id"]]
    items.append(item)


def operator(
    operator_id: str,
    description: str,
    inputs: list[str],
    outputs: list[str],
    preconditions: list[str],
    postconditions: list[str],
    permissions: list[str],
    methods: list[str],
    rollback: str,
) -> dict:
    return {
        "id": operator_id,
        "version": "0.1.0",
        "description": description,
        "input_types": inputs,
        "output_types": outputs,
        "preconditions": preconditions,
        "postconditions": postconditions,
        "permissions": permissions,
        "execution_methods": methods,
        "deterministic": True,
        "randomness_seed_required": False,
        "rollback": {"supported": True, "strategy": rollback},
    }


def validator(
    validator_id: str,
    claims: list[str],
    evidence_types: list[str],
    strategy: str,
) -> dict:
    return {
        "id": validator_id,
        "version": "0.1.0",
        "claims": claims,
        "independence_class": "independent",
        "evidence_types": evidence_types,
        "deterministic": True,
        "implementation": {
            "crate": "ergaxiom-print-ready-poster-preflight-certified-path-runtime",
            "strategy": strategy,
        },
    }


def update_capsule() -> None:
    capsule = load_json(CAPSULE_PATH)
    capsule["version"] = CAPSULE_VERSION
    replace_by_id(
        capsule["job_types"],
        {
            "id": JOB_ID,
            "description": "Preflight and export one flat vector outlined poster only after independently proving bleed, safe area, PDF page boxes, resources, color spaces and security boundaries.",
            "specialization": "print_preflight",
            "required_inputs": ["source_svg", "print_specification"],
            "required_outputs": ["editable_master", "delivery_pdf", "evidence_bundle"],
            "required_constraints": CONSTRAINTS,
            "operator_ids": OPERATORS,
            "minimum_assurance_level": "E3",
        },
    )
    operator_definitions = [
        operator(
            "print.validate_source",
            "Parse the immutable restricted SVG and independently measure bleed canvas, background coverage, safe area, palette, raster count, live text and path profile.",
            ["source_svg", "print_specification"],
            ["print_source_validation_report"],
            ["input_digests_match_contract", "print_specification_is_resolved", "workspace_is_isolated"],
            ["all_mandatory_source_print_rules_are_measured", "source_material_remains_immutable"],
            ["filesystem.read:contract_inputs", "application.control:print_validator"],
            ["document_model", "signed_adapter"],
            "discard validation report and isolated parse state",
        ),
        operator(
            "print.export_pdf_with_inkscape",
            "Export the accepted outlined vector SVG through pinned Inkscape and deterministically normalize PDF MediaBox, TrimBox, BleedBox and CropBox.",
            ["source_svg", "print_specification", "print_source_validation_report"],
            ["editable_master", "raw_pdf", "delivery_pdf", "print_execution_record"],
            ["source_validation_is_accepted", "trusted_inkscape_identity_is_bound", "output_paths_are_new"],
            ["adapter_record_is_verified", "source_material_remains_immutable", "normalized_pdf_boxes_match_specification"],
            ["filesystem.read:contract_inputs", "filesystem.write:declared_output", "application.control:inkscape"],
            ["application_api", "cli", "signed_adapter"],
            "discard editable staging document, raw PDF and normalized PDF",
        ),
        operator(
            "print.certify_preflight",
            "Verify signed execution evidence, independently reparse source SVG and delivery PDF, reassess the authorized trace and issue an Ed25519 Acceptance Certificate.",
            ["source_svg", "print_specification", "editable_master", "raw_pdf", "delivery_pdf", "validator_reports", "authorized_execution_trace"],
            ["evidence_bundle", "acceptance_certificate"],
            ["signed_execution_evidence_verifies", "all_mandatory_validator_reports_are_bound", "authorized_trace_conforms_to_plan"],
            ["evidence_bundle_is_independently_accepted", "acceptance_certificate_verifies_against_exact_bundle"],
            ["filesystem.read:isolated_workspace", "filesystem.write:declared_output", "secret.use:attestation_signing_key"],
            ["signed_adapter"],
            "discard unsigned bundle and certificate material",
        ),
    ]
    for item in operator_definitions:
        replace_by_id(capsule["operators"], item)

    validator_definitions = [
        validator("print.svg.structure", ["restricted_svg_profile"], ["parsed_svg_snapshot"], "allow only svg, g, rect and absolute M/L/H/V/Z path material with no effects or external references"),
        validator("print.canvas.dimensions", ["canvas_dimensions_match"], ["parsed_svg_geometry"], "compare width, height and viewBox with trim plus twice the declared bleed"),
        validator("print.bleed.coverage", ["bleed_coverage"], ["parsed_svg_geometry"], "measure the declared background rectangle against every bleed-canvas edge"),
        validator("print.safe_area.geometry", ["safe_area_satisfied"], ["parsed_svg_geometry"], "bound every non-background rectangle and certified path inside bleed plus safe margin"),
        validator("print.palette.allowlist", ["palette_violations"], ["parsed_svg_snapshot"], "compare every flat fill with exact lowercase approved #rrggbb values"),
        validator("print.pdf.vector_only", ["vector_only"], ["parsed_pdf_resources"], "independently prove the page contains no raster image XObjects"),
        validator("print.pdf.fonts_outlined", ["fonts_outlined"], ["parsed_pdf_resources"], "independently prove the page contains no PDF font resources or live SVG text"),
        validator("print.pdf.page", ["page_count"], ["parsed_pdf_page_tree"], "recompute the page tree and require exactly one poster page"),
        validator("print.pdf.boxes", ["media_box_match", "trim_box_match", "bleed_box_match", "crop_box_match"], ["parsed_pdf_page_boxes"], "recompute MediaBox, TrimBox, BleedBox and CropBox from the print specification"),
        validator("print.pdf.version", ["pdf_version"], ["parsed_pdf_header"], "parse and compare the normalized PDF header version"),
        validator("print.pdf.color_spaces", ["allowed_color_spaces"], ["decoded_pdf_content"], "decode page content and accept only explicitly allowed DeviceRGB or DeviceGray operators"),
        validator("print.pdf.transparency", ["transparency_absent"], ["parsed_pdf_resources"], "reject soft masks, transparent ExtGState values and unsupported transparency groups"),
        validator("print.pdf.security", ["external_actions_absent"], ["parsed_pdf_catalog"], "reject encryption, annotations, JavaScript, launch actions, AcroForm and embedded files"),
        validator("print.source.immutability", ["source_immutable"], ["pre_execution_digest", "post_execution_digest"], "compare sealed source SVG bytes before and after execution"),
        validator("print.inkscape.integration", ["inkscape_export_verified"], ["application_identity", "adapter_receipt", "signed_execution_record"], "verify pinned Inkscape identity and proof-bound PDF export receipt bindings"),
    ]
    for item in validator_definitions:
        replace_by_id(capsule["validators"], item)

    capsule["policies"]["minimum_assurance_by_job_type"][JOB_ID] = "E3"
    write_json(CAPSULE_PATH, capsule)


def update_version_bindings() -> None:
    for path in [
        ROOT / "examples/work-contracts/social-media-static-post.json",
        ROOT / "examples/work-contracts/image-background-cleanup.json",
        ROOT / "examples/work-contracts/brand-compliant-image-export.json",
    ]:
        document = load_json(path)
        document["profession"]["capsule_version"] = CAPSULE_VERSION
        write_json(path, document)

    text_files = [
        ROOT / "crates/intent-contract-compiler-runtime/tests/static_social_post.rs",
        ROOT / "crates/background-cleanup-certified-path-runtime/tests/path.rs",
        ROOT / "crates/brand-compliant-export-certified-path-runtime/tests/path.rs",
        ROOT / ".github/workflows/background-cleanup-certified-path.yml",
        ROOT / ".github/workflows/brand-compliant-export-certified-path.yml",
        ROOT / "docs/architecture/38-brand-compliant-export-certified-path.md",
    ]
    for path in text_files:
        text = path.read_text(encoding="utf-8")
        text = text.replace("0.5.0", CAPSULE_VERSION)
        path.write_text(text, encoding="utf-8")


def constraint(identifier: str, claim: str, subject: str, expected, unit, source: str) -> dict:
    return {
        "id": identifier,
        "claim": claim,
        "subject": subject,
        "operator": "eq",
        "expected": expected,
        "unit": unit,
        "tolerance": 0,
        "mandatory": True,
        "source": source,
    }


def build_example_contract() -> None:
    specification_digest = "b" * 64
    source_digest = "a" * 64
    hard = [
        constraint("restricted_svg_profile", "The source uses only the certified vector poster SVG profile.", "source_svg.restricted_profile", True, None, "certified_job_profile"),
        constraint("canvas_dimensions_match", "The bleed canvas matches trim plus twice the declared bleed.", "source_svg.canvas_dimensions_match", True, None, "print_specification"),
        constraint("bleed_coverage", "The approved background covers the complete bleed canvas.", "source_svg.bleed_coverage", True, None, "print_specification"),
        constraint("safe_area_satisfied", "Every non-background vector bound is inside the safe area.", "source_svg.safe_area_satisfied", True, None, "print_specification"),
        constraint("palette_violations", "Every fill belongs to the exact approved print palette.", "source_svg.palette_violations", 0, "count", "print_specification"),
        constraint("vector_only", "The PDF contains no raster image XObjects.", "delivery_pdf.vector_only", True, None, "certified_job_profile"),
        constraint("fonts_outlined", "The source and PDF contain no live text or fonts.", "delivery_pdf.fonts_outlined", True, None, "certified_job_profile"),
        constraint("page_count", "The PDF contains exactly one page.", "delivery_pdf.page_count", 1, "page", "print_specification"),
        constraint("media_box_match", "MediaBox matches the bleed canvas.", "delivery_pdf.media_box_match", True, None, "print_specification"),
        constraint("trim_box_match", "TrimBox matches trim and bleed inset.", "delivery_pdf.trim_box_match", True, None, "print_specification"),
        constraint("bleed_box_match", "BleedBox equals MediaBox.", "delivery_pdf.bleed_box_match", True, None, "print_specification"),
        constraint("crop_box_match", "CropBox equals MediaBox.", "delivery_pdf.crop_box_match", True, None, "print_specification"),
        constraint("pdf_version", "The normalized PDF version is 1.5.", "delivery_pdf.pdf_version", "1.5", None, "print_specification"),
        constraint("allowed_color_spaces", "Only allowed PDF color spaces are used.", "delivery_pdf.allowed_color_spaces", True, None, "print_specification"),
        constraint("transparency_absent", "Unsupported transparency is absent.", "delivery_pdf.transparency_absent", True, None, "certified_job_profile"),
        constraint("external_actions_absent", "Interactive, encrypted and external-action PDF features are absent.", "delivery_pdf.external_actions_absent", True, None, "certified_job_profile"),
        constraint("source_immutable", "The source SVG remains byte-identical.", "source_svg.immutable", True, None, "execution_record"),
        constraint("inkscape_export_verified", "The PDF is exported through pinned Inkscape evidence.", "delivery_pdf.inkscape_export_verified", True, None, "trusted_application_identity"),
    ]
    obligation_rows = [
        ("restricted_svg_profile", "print.svg.structure", "parsed_svg_snapshot"),
        ("canvas_dimensions_match", "print.canvas.dimensions", "parsed_svg_geometry"),
        ("bleed_coverage", "print.bleed.coverage", "parsed_svg_geometry"),
        ("safe_area_satisfied", "print.safe_area.geometry", "parsed_svg_geometry"),
        ("palette_violations", "print.palette.allowlist", "parsed_svg_snapshot"),
        ("vector_only", "print.pdf.vector_only", "parsed_pdf_resources"),
        ("fonts_outlined", "print.pdf.fonts_outlined", "parsed_pdf_resources"),
        ("page_count", "print.pdf.page", "parsed_pdf_page_tree"),
        ("media_box_match", "print.pdf.boxes", "parsed_pdf_page_boxes"),
        ("trim_box_match", "print.pdf.boxes", "parsed_pdf_page_boxes"),
        ("bleed_box_match", "print.pdf.boxes", "parsed_pdf_page_boxes"),
        ("crop_box_match", "print.pdf.boxes", "parsed_pdf_page_boxes"),
        ("pdf_version", "print.pdf.version", "parsed_pdf_header"),
        ("allowed_color_spaces", "print.pdf.color_spaces", "decoded_pdf_content"),
        ("transparency_absent", "print.pdf.transparency", "parsed_pdf_resources"),
        ("external_actions_absent", "print.pdf.security", "parsed_pdf_catalog"),
        ("source_immutable", "print.source.immutability", "pre_execution_digest"),
        ("inkscape_export_verified", "print.inkscape.integration", "signed_execution_record"),
    ]
    obligations = [
        {
            "id": f"proof.{claim}",
            "constraint_id": claim,
            "validator_ids": [validator_id],
            "mandatory": True,
            "independence_class": "independent",
            "evidence_types": [evidence_type],
        }
        for claim, validator_id, evidence_type in obligation_rows
    ]
    contract = {
        "schema_version": "0.2.0",
        "contract_id": "contract.example.print-ready-poster-preflight.0001",
        "created_at": "2026-07-24T13:00:00Z",
        "request": {
            "original_text": "Preflight this outlined vector poster against the supplied A4 print specification.",
            "language": "en",
            "requester_id": "example.print-preflight",
        },
        "profession": {
            "capsule_id": "ergaxiom.profession.graphic-designer",
            "capsule_version": CAPSULE_VERSION,
            "specialization": "print_production",
        },
        "job_type": JOB_ID,
        "environment": {
            "os": None,
            "applications": [{"application_id": "org.inkscape.Inkscape", "required_version": "1.2-1.4"}],
            "network_mode": "denied",
        },
        "inputs": [
            {"id": "source_svg", "kind": "source_svg", "uri": "contract://inputs/poster.svg", "integrity": {"algorithm": "sha256", "digest": source_digest}, "media_type": "image/svg+xml", "immutable": True},
            {"id": "print_specification", "kind": "print_specification", "uri": "contract://inputs/print-specification.json", "integrity": {"algorithm": "sha256", "digest": specification_digest}, "media_type": "application/json", "immutable": True},
        ],
        "outputs": [
            {"id": "editable_master", "kind": "editable_master", "destination": "contract://outputs/print-ready-poster.svg", "media_type": "image/svg+xml", "required": True},
            {"id": "delivery_pdf", "kind": "delivery_pdf", "destination": "contract://outputs/print-ready-poster.pdf", "media_type": "application/pdf", "required": True},
            {"id": "evidence_bundle", "kind": "evidence_bundle", "destination": "contract://outputs/print-ready-poster-evidence.json", "media_type": "application/json", "required": True},
        ],
        "requirements": {"hard": hard, "preferences": [], "unknowns": []},
        "permissions": [
            {"capability": "filesystem", "resource": "contract://inputs/*", "access": "read", "constraints": {"immutable": True}},
            {"capability": "filesystem", "resource": "contract://outputs/*", "access": "write", "constraints": {"overwrite": False}},
            {"capability": "print-validator", "resource": "isolated-workspace", "access": "control", "constraints": {"network": False}},
            {"capability": "design-editor", "resource": "print-export", "access": "control", "constraints": {"network": False}},
        ],
        "proof_obligations": obligations,
        "approval_policy": {"require_pre_execution_approval": True, "require_irreversible_action_approval": True, "approval_ttl_seconds": 300},
        "acceptance": {"minimum_assurance_level": "E3", "unknowns_must_be_empty": True, "all_mandatory_proofs_must_pass": True, "validator_conflicts_allowed": False},
        "metadata": {"compiler": "ergaxiom-print-ready-poster-preflight-certified-path-runtime", "compiler_version": "0.1.0", "intent_kind": JOB_ID, "print_specification_digest": specification_digest, "restricted_svg_profile": "flat_vector_outlined_path_poster_v1", "subjective_print_quality_is_hard_acceptance": False, "deterministic": True, "implicit_defaults": False},
    }
    write_json(ROOT / "examples/work-contracts/print-ready-poster-preflight.json", contract)


def update_workspace() -> None:
    path = ROOT / "Cargo.toml"
    text = path.read_text(encoding="utf-8")
    member = '  "crates/print-ready-poster-preflight-certified-path-runtime",\n'
    if member not in text:
        anchor = '  "crates/png-srgb-normalizer-runtime",\n'
        if anchor not in text:
            raise SystemExit("workspace member anchor not found")
        text = text.replace(anchor, anchor + member, 1)
    path.write_text(text, encoding="utf-8")


def main() -> None:
    update_capsule()
    update_version_bindings()
    build_example_contract()
    update_workspace()
    print("PRINT PREFLIGHT BOOTSTRAP PASSED")


if __name__ == "__main__":
    main()
