# Find Entity Reactions Policy

## Description

This policy decides whether a caller may list reactions attached to a specific entity. The decision composes two checks which both must pass:

- The caller must be permitted to find entity reactions (role-based rules mirroring `entityReactions/findEntityReactions`).
- The caller must be permitted to view the target entity (visibility rules from `entities/findEntityById`).

Summary:

- Admin and editor roles may list entity reactions (email verification enforced).
- Members and visitors may list entity reactions when email-verified and visibility/ownership rules allow.

## Fields

- `encodedJwt`: Encoded JWT string.
- `originalRecord`: The entity record used to evaluate visibility.
