# Find Lists By Entity ID Policy

## Description

This policy allows a caller to query lists for a given entity only when both of the following are true:

- The caller is permitted to query lists (same logic as `findLists`).
  - Admin and editor users are allowed to find lists.
  - Members and visitors can find lists if their email is verified.
- The caller is permitted to see the provided `originalRecord` (same logic as `findEntityById`).
  - Admin and editor users are always allowed to retrieve the entity.
  - Members can view the record if one of the following entity visibility conditions is satisfied:
    - The original record belongs to the user and is not passive (either 'active' or 'pending').
    - The original record belongs to one of the user's groups and is not private (either 'public' or 'protected') and is not passive (either 'active' or 'pending').
    - The original record is public and active.
    - The original record contains the user's id in `viewerUsers` and the record is active.
    - The original record contains at least one of the user's groups in `viewerGroups`, the record is active, and the record is not private (either 'public' or 'protected').
  - Visitors can view the entity only when it is public and active.

In short: permission to "find lists through an entity" requires both list-query permission and entity visibility permission. The entity being checked is supplied in `input.originalRecord`.

## Fields

- `encodedJwt`: Encoded JWT string containing user claims (roles, groups, sub, etc.).
- `appShortcode`: Shortcode of the application used by the role-matching helpers.
- `originalRecord`: The entity record being queried by its ID (used to evaluate visibility rules).

