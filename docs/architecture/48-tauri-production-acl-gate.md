# Tauri Production ACL Gate

## Status

This gate extends the pinned Tauri production startup boundary with independent Windows owner and DACL verification. It does not enable production issuance.

## Protected inputs

Before any production configuration is accepted, the backend verifies:

- the backend deployment manifest and external digest pin;
- the running desktop executable;
- the signer service manifest and executable;
- the governance policy, caller allowlist and deployment policy; and
- the production trust-store root.

Each file or directory and its immediate parent must be an absolute, existing, non-reparse path. The owner must be LocalSystem (`S-1-5-18`) or Builtin Administrators (`S-1-5-32-544`). The DACL must be protected from inheritance. Standard allow ACEs may grant read or execute access to other principals, but any write, append, child creation, deletion, DACL change, owner change, generic write, generic all or maximum-allowed grant is accepted only for LocalSystem or Builtin Administrators. Unknown ACE layouts fail closed.

## Renderer boundary

The renderer receives only the boolean `configuration_acl_verified` and bounded public status codes. It receives no owner SID, ACE, filesystem path or security descriptor.

## Failure behavior

A missing, malformed, reparse, user-owned, inheritance-enabled or user-writable path leaves `production_issuance_enabled` false and reports one of these bounded states:

- `production_configuration_acl_rejected`;
- `production_backend_acl_rejected`; or
- `production_signer_configuration_acl_rejected`.

## Remaining gate

ACL verification proves that the installed public configuration cannot be modified through an ordinary non-administrator file grant. It does not authenticate a live signer-service instance. The next slice must add a purpose-locked service identity proof that cannot be repurposed into arbitrary digest signing, then bind its trust-state and deployment identity to the already verified startup configuration.
