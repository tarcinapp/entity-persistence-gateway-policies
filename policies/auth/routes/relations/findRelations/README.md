# Find Relations Policy

## Description

This policy evaluates the user's role, email verification status and request payload to decide if user can find relations.

- Admin and editor users are allowed to find relations.
- Members and visitors are allowed to find relations if their email is validated.
- Deciding what a user can actually see is handled via query variables at the gateway — the gateway should narrow the search using ownership/visibility filters so the policy can remain lightweight.

## Fields

- `encodedJwt`: Encoded JWT string.
