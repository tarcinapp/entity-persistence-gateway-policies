# Find List Reaction by ID Policy

## Description

This policy decides whether a caller may retrieve a single reaction attached to a list (find by reaction id).

The decision composes two checks which both must pass (for non-admin/editor roles):

- The caller must be permitted to view the parent list provided in `input.source` (mirrors `lists/findListById` visibility/ownership/viewer rules).
- The caller must be permitted to view the reaction provided in `input.originalRecord` (uses the shared `originalRecord` helpers).

Summary:

- Admin and editor roles may retrieve the reaction (email verification enforced).
- Members may retrieve the reaction when email-verified and both the parent list and the reaction satisfy the visibility/ownership/viewer rules.
- Visitors may retrieve only active and public reactions when the parent list is also public and active.

## Fields

- `encodedJwt`: Encoded JWT string representing the caller.
- `source`: The parent list metadata (used to evaluate list visibility). Expected fields: `_id`, `_visibility`, `_validFromDateTime`, `_validUntilDateTime`, `_ownerUsers`, `_ownerGroups`, `_viewerUsers`, `_viewerGroups`, etc.
- `originalRecord`: The reaction record being queried by its ID. Expected shape follows the `originalRecord` helpers.
