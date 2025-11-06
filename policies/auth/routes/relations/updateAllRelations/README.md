# Update All Relations Policy

## Description

This policy restricts bulk update of relation records to administrator and editor users.

- Allowed roles: admin and editor within the relations scope (and global app admin/editor). Email must be verified.

## Fields

- `encodedJwt`: Encoded JWT string.
- `requestPayload`: The payload containing the relations to be updated.
