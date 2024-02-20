# Find Lists Policy

## Description

This policy evaluates the user's role, email verification status, and request payload to determine if a user can access lists.

- Admin and editor users are allowed to find lists.
- Members and visitors can find lists if their email is validated.
- The policy for what a user can see is managed through query variables at the gateway.

## Fields

- `encodedJwt`: Encoded JWT string.
