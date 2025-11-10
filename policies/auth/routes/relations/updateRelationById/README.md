# Update Relation by ID Policy

## Description

This policy evaluates the caller's role, email verification status, the request payload, and the original relation record (which contains nested `fromMetadata` and `toMetadata`) to decide whether the caller may update (PATCH) the relation by its id.

High-level semantics:

- Relations do not carry ownership or viewer lists themselves — ownership and visibility are derived from the nested metadata supplied in `originalRecord`:
  - `_fromMetadata` — the source list's metadata (used to check list ownership and list visibility/validity)
  - `_toMetadata` — the target entity's metadata (used to check whether the caller can see the target entity)
- Admins and Editors
  - Must have verified email.
  - Cannot include fields in the payload that they are not allowed to see.
  - Forbidden-for-update fields (per role) must remain unchanged compared to `originalRecord`.
  - Admins and Editors may retarget ids on PATCH (repair/merge workflows) subject to the above constraints.
- Members
  - Must have verified email.
  - Cannot include fields that are forbidden to see; must preserve forbidden-for-update fields (omission allowed, change denied).
  - Cannot retarget `_listId` or `_entityId` (must remain unchanged).
  - Must own the referenced list (via `_fromMetadata._ownerUsers` or `_fromMetadata._ownerGroups` when visibility allows).
  - Must be able to see both the referenced list and the target entity according to standard visibility rules (owner precedence, groups, viewer lists, public/protected/private semantics, and active/pending/passive time windows).
  - Members cannot update passive (expired) relations.
  - Field-level updates for `_validFromDateTime` (approvals) and `_validUntilDateTime` (inactivations) are strictly controlled: members may only set these within configured ranges or if they possess the corresponding field-level role.
  - Important: For member operations, both the referenced list (`_fromMetadata`) and the target entity (`_toMetadata`) must be in the active state (validFrom in the past and not expired). Pending or expired endpoints are not permitted for relation updates by members.
- Visitors
  - Visitors cannot update relations.

Notes:
- Missing nested metadata in `originalRecord` should be treated as denial — ownership/visibility cannot be established.
- Relations themselves carry only validity fields at the top level; ownership/visibility is derived from the endpoints.
- The policy enforces field-level visibility checks using the relations forbidden-fields table so callers cannot submit fields they cannot see.

## Fields

- `encodedJwt`: Encoded JWT string used to derive caller identity, roles and groups.
- `requestPayload`: Partial relation fields to update (PATCH semantics).
- `originalRecord`: Existing relation with `_fromMetadata` and `_toMetadata` populated; used to evaluate ownership, visibility, and time-state.

