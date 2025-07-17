# Update All Lists Policy

## Description

This policy evaluates the user's role to decide if updating the lists as a whole is allowed.

- Only administrators and editors are allowed to perform this operation.
- Both roles require email verification.
- The payload cannot contain any fields that the user is not allowed to see or update.

## Fields

- `encodedJwt`: Encoded JWT string.
- `requestPayload`: The payload containing the lists to be updated.
