# Find Relation by ID Policy

## Description

This policy evaluates the user's role, email verification status, and the `originalRecord` (relation record with nested `_fromMetadata` and `_toMetadata`) to determine if a caller is allowed to retrieve the relation by its ID.

The key principle for relation visibility is that a caller may see a relation only when they are permitted to see both the source (list) and the target (entity). The policy uses the same visibility/ownership semantics applied in `findListById` and `findEntityById` but evaluates them against the nested metadata contained in `originalRecord`:

- `_fromMetadata` — metadata for the source list (used with list visibility rules).
- `_toMetadata` — metadata for the target entity (used with entity visibility rules).

- *Admin and Editor users*: allowed to retrieve the relation provided their email is verified.

- *Member users*: allowed to retrieve the relation if their email is verified AND they can see both the source and the target. "Can see" follows the same rules used for lists and entities (one of: direct owner and not passive; group owner and not private and not passive; public and active; viewerUsers and active; viewerGroups and active and not private). Owner precedence is preserved: if the user is in `_ownerUsers`, group-based ownership checks are not consulted.

- *Visitor users*: allowed to retrieve the relation only when their email is verified AND both the source and the target are public and active.

Notes:

- Relation records themselves typically do not contain `_ownerUsers`, `_ownerGroups`, `_viewerUsers`, or `_viewerGroups`. The policy therefore relies on the nested `_fromMetadata` and `_toMetadata` supplied in `originalRecord` for all ownership and visibility decisions.
- Active / passive evaluation is based on `_validFromDateTime` and `_validUntilDateTime`.
- Owner precedence is preserved: if the user is present in `_ownerUsers`, group-based ownership checks are not consulted.

## Fields

- `encodedJwt`: Encoded JWT string provided by the caller (token payload is used for ownership and groups).
- `originalRecord`: The relation retrieval result containing nested metadata used for visibility and ownership checks. Important keys inside `originalRecord`:
  - `_fromMetadata`: source list metadata (owner/viewer/visibility/validity fields)
  - `_toMetadata`: target entity metadata (owner/viewer/visibility/validity fields)
