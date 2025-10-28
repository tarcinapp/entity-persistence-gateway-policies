# Count Entities Policy

## Description

This policy evaluates the user's role, email verification status, and request payload to determine whether the user can count lists. All roles are allowed to call the count operation as long as they have their email address validated.

## Fields

- `encodedJwt`: Encoded JWT string.
