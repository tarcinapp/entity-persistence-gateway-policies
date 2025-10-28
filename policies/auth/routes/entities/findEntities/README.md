# Find Entities Policy

## Description

This policy evaluates the user's role, email verification status, and request payload to determine if a user can access entities.

- Admin and editor users are allowed to find entities.
- Members and visitors can find entities if their email is validated.
- The policy for what a user can see is managed through query variables at the gateway.

## Fields

- `encodedJwt`: Encoded JWT string.
