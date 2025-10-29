# Find List Reactions Policy

## Description

This policy decides whether a caller may list reactions attached to a specific list. The decision composes two checks which both must pass:

- The caller must be permitted to find list reactions (role-based rules mirroring `listReactions/findListReactions`).
- The caller must be permitted to view the target list (visibility rules from `lists/findListById`).

Summary:

- Admin and editor roles may list list reactions (email verification enforced).
- Members and visitors may list list reactions when email-verified and visibility/ownership rules allow.

## Fields

- `encodedJwt`: Encoded JWT string.
- `originalRecord`: The list record used to evaluate visibility.
