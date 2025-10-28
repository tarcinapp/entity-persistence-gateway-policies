# Create Entity By List ID Policy

## Description

This policy evaluates whether a caller may create an entity under a specific list. The decision requires two independent checks:

- The caller must be permitted to create the entity (same creation rules as `createEntity`).
- The caller must be permitted to view the target list (same visibility rules as `findListById`).

If either check fails, the overall operation is denied.

Creation rules summary (role-based):

- **Admin Users:** allowed to create with minimal restrictions.
- **Editor Users:** allowed to create when email-verified and not including forbidden fields (e.g. `_createdBy`, `_createdDateTime`, etc.).
- **Member Users:** allowed to create when email-verified, not including forbidden fields, and when any `_ownerGroups` in the payload match groups present in the token.

List visibility rules summary (derived from `findListById`):

- **Admin / Editor:** allowed to view lists (subject to email verification where required).
- **Member:** allowed when the original list record belongs to the user, belongs to the user's groups (and is not private), is public and active, or when the user/group appears in viewer lists and activity/privacy flags allow.
- **Visitor:** allowed only for public and active lists.

## Fields

- `encodedJwt`: Encoded JWT string.
- `requestPayload`: Request payload JSON object (entity fields the caller is attempting to set).
- `originalRecord`: The list record being referenced (used to evaluate visibility and ownership).

## Notes

- This README follows the same structure and intent as other policy READMEs in this repository (see `policies/auth/routes/entities/createEntity/README.md`).
- Tests for this policy are in `policy_test.rego` in the same directory.
