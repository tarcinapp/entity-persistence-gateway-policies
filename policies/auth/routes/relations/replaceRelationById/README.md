# Replace Relation by ID Policy

## Description

This policy evaluates the caller's role, email verification status, the request payload, and the original relation record (which contains nested `fromMetadata` and `toMetadata`) to decide whether the caller may replace the relation using its id.

High-level semantics:

- Relations do not carry ownership or viewer lists themselves. Ownership and visibility are derived from the nested metadata supplied in `originalRecord`:
  - `_fromMetadata`: the source list's metadata (used to check list ownership and list visibility/validity)
  - `_toMetadata`: the target entity's metadata (used to check whether the caller can see the target entity)
- Admins and Editors
  - Must have verified email.
  - Cannot include fields in the payload that they are not allowed to see.
  - Forbidden-for-update fields (per role) must remain unchanged compared to `originalRecord`.
  - Admins and Editors are allowed to operate across lists/entities (not constrained by membership rules) but are still subject to email verification and forbidden-field constraints.
- Members
  - Must have verified email.
  - Must own the referenced list (via `_fromMetadata._ownerUsers` or `_fromMetadata._ownerGroups` when visibility allows).
  - Must be able to see both the referenced list and the target entity according to the same visibility rules as `findListById`/`findEntityById` (owner precedence, groups, viewer lists, public/protected/private semantics, and active/pending/passive time windows).
  - Cannot change the relation's referenced ids (`_listId` or `_entityId`) in a replace-by-id operation.
  - Members cannot update passive relations.
  - Field-level updates for `_validFromDateTime` (approvals) and `_validUntilDateTime` (inactivations) are strictly controlled: members may only set these within configured ranges or if they possess the corresponding field-level role.
   - Important: For member operations, both the referenced list (`_fromMetadata`) and the target entity (`_toMetadata`) must be in the active state (validFrom in the past and not expired). Pending or expired endpoints are not permitted for relation updates by members.
- Visitors
  - Visitors cannot replace relations.

Notes:
- Missing nested metadata in `originalRecord` should be treated as denial. Ownership/visibility cannot be established.
- The policy enforces field-level visibility checks using the relations forbidden-fields table so callers cannot submit fields they cannot see.

## Fields

- `encodedJwt`: Encoded JWT string used to derive caller identity, roles and groups.
- `requestPayload`: Request payload JSON object for the replace operation.
- `originalRecord`: The existing relation record retrieved by id; must include `_fromMetadata` (list metadata) and `_toMetadata` (entity metadata). These are used for ownership/visibility/time checks.
