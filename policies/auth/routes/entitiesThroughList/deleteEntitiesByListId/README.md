# Delete Entities by List ID Policy

## Description

This policy restricts deletion of entities under a given list to administrator users only.

Only callers with the appropriate admin role (as determined by `data.policies.util.entities.roles`) and an email-verified token are allowed to perform the operation.

## Fields

- `encodedJwt`: Encoded JWT string.
- `requestPath`: The request path indicating the target list (optional for policy evaluation).
