# Security Policy

## Supported versions

Ergaxiom is pre-alpha. Security fixes are applied only to the latest commit on the default branch and to an explicitly identified release candidate. No older commit, unsigned binary or locally modified build is supported as a production release.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/tayfunates10/ergaxiom/security/advisories/new). Do not open a public issue for signing-key exposure, trust-state bypass, capability widening, evidence forgery, path traversal, arbitrary execution or installer/update vulnerabilities.

Include the affected commit, platform, trust role, reproduction steps, expected boundary, observed behavior and whether private material or user artifacts may have been exposed. Remove real secrets and personal data from the report.

## Security claim boundary

An Ergaxiom result is accepted only for the exact claims and artifacts bound into its independently verified Evidence Bundle and Acceptance Certificate. A screenshot, application success response, model assertion, unsigned executable or passing renderer state is not proof of accepted work.

Unsigned Windows candidates are for development validation only. They are not production releases until Authenticode, trusted timestamp, certificate-chain, installer provenance, controlled-hardware and upgrade/rollback gates independently pass.
