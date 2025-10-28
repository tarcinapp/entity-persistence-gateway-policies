# Find Entity by ID Policy

## Description

This policy evaluates the user's role, email verification status, and original record to decide if a user can retrieve the record.

- Admin and editor users are always allowed to retrieve the entity.
- Members and visitors can retrieve entities if their email is validated.
- Members can view the record if one of the following conditions is true for the queried record:
  - The original record belongs to the user and is not passive (either 'active' or 'pending').
  - The original record belongs to one of the user's groups and is not private (either public or protected) and is not passive (either 'active' or 'pending').
  - The original record is public and active.
  - The original record contains user's id in `viewerUsers` and record is active
  - The original record contains at least one of the user's group in `viewerGroups` and record is active, and record is not private (either protected or public)
- Visitors are allowed to retrieve only active and public entities`

## Fields

- `encodedJwt`: Encoded JWT string.
- `originalRecord`: The record being queried by its ID.
