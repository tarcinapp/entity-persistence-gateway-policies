# Find Entity by ID Policy

## Description

This policy evaluates the user's role, email verification status, and original record to decide if a user can retrieve the record.

- Admin and editor users are always allowed to retrieve the entity.
- Members and visitors can retrieve entities if their email is validated.
- Members can view the record if one of the following conditions is true for the queried record:
  - The original record belongs to the user and is not passive (either 'active' or 'pending').
  - The original record belongs to one of the user's groups and is not private (either public or protected) and is not passive (either 'active' or 'pending').
  - The original record is public and active.

## Fields

- `encodedJwt`: Encoded JWT string.
- `originalRecord`: The record being queried by its ID.
