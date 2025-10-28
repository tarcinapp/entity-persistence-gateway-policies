# Find Entities by List ID Policy

## Description

This policy decides whether a caller may list entities belonging to a specific list. The decision requires two checks:

- The caller must be permitted to find entities (same role-based rules as `entities/findEntities`).
- The caller must be permitted to view the target list (same visibility rules as `lists/findListById`).

Both checks must pass for the request to be allowed.

## Behavior

- Entity-find rules:
  - Admin and editor roles may list entities (email verification enforced).
  - Members may list entities when email-verified.
  - Visitors may list entities when email-verified.

- List visibility rules (used as an additional precondition):
  - Admins and editors may view the list (email verification enforced).
  - Members may view the list when ownership/viewer/private/active flags permit.
  - Visitors may view only public and active lists.

## Fields

- `encodedJwt`: Encoded JWT string.
- `originalRecord`: The list record used to evaluate visibility.

## Notes

- This policy composes two existing policy concerns (entity-find and list-visibility) to ensure callers can both view the list and perform entity-listing operations under it.
