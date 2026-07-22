# Inkscape Adapter v1

## Purpose

This phase connects the Graphic Designer profession capsule to a real vector-design application without falling back to coordinate clicks or unverifiable visual guesses.

The adapter uses two independently checkable control surfaces:

1. the SVG document model for a narrowly declared edit;
2. the Inkscape command-line renderer for the delivery PNG.

The first certified operator pair is:

- `design.compose_text` — replace one exact direct text node selected by unique SVG `id`;
- `design.export_raster` — render the edited SVG to an explicitly sized PNG.

## Certified application range

The initial implementation accepts Inkscape 1.2, 1.3 and 1.4 only. The executable is rejected unless its SHA-256 exactly matches the trusted digest supplied by the execution environment.

A newer release is not silently accepted. It must pass the adapter conformance suite before the certified range is expanded.

## Transaction

The adapter performs the following transaction:

1. validate request schema and resource bounds;
2. canonicalize the source and isolated output paths;
3. reject source/output aliases, existing outputs and parent traversal;
4. measure the source SVG SHA-256;
5. parse an independent semantic snapshot of the SVG;
6. find one unique target `id`;
7. reject nested target content, `tspan`, DTD material and multiple direct text segments;
8. write an isolated SVG copy with only the declared text replacement;
9. independently parse the output SVG;
10. prove that canvas properties and every non-target ID-bound element are unchanged;
11. invoke the digest-pinned Inkscape binary for page export;
12. read PNG signature and IHDR dimensions independently of Inkscape;
13. create a deterministic execution record containing all measured digests.

## Fail-closed rules

Execution fails before acceptance when any of these conditions occurs:

- the Inkscape executable digest differs;
- the version is outside 1.2–1.4;
- the source digest differs from the request;
- the source would be edited in place;
- an output already exists;
- the target SVG ID is absent or duplicated;
- the target contains nested elements or more than one direct text segment;
- a DTD is present;
- any undeclared SVG semantic change is observed;
- Inkscape exits unsuccessfully;
- the PNG signature or IHDR is malformed;
- exported dimensions differ from the request.

## Evidence boundary

The adapter does not claim that the composition is aesthetically good. It proves only the machine-checkable claims declared by this operator:

- approved copy was placed into the exact target object;
- unrelated ID-bound SVG objects and canvas declarations remained unchanged;
- a specific trusted Inkscape executable performed the render;
- the delivery artifact is a PNG with the requested dimensions;
- editable and raster outputs have measured SHA-256 digests.

A later phase will bind this execution record to the signed capability receipt and Graphic Designer delivery certificate.

## Continuous verification

The dedicated GitHub Actions workflow installs a real Inkscape package on Ubuntu, measures its executable digest, runs the document-model attack tests, performs a real SVG edit and requests a 512×512 PNG export. The PNG is accepted only after independent IHDR inspection.
