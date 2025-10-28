# Find Entity Children Policy

## Description

This policy evaluates the user's role, email verification status, and original record to decide if a user can retrieve the entity's children.

To allow caller to findChildren of the entity, caller must be able to find the entity given in the originalRecord.

- Admin and editor users are always allowed to retrieve the entity children.
- Members and visitors can retrieve entity children if their email is validated.
- Members can view the record's children if one of the following conditions is true for the parent entity record:
  - The original record belongs to the user and is not passive (either 'active' or 'pending').
  - The original record belongs to one of the user's groups and is not private (either public or protected) and is not passive (either 'active' or 'pending').
  - The original record is public and active.
  - The original record contains user's id in `viewerUsers` and record is active
  - The original record contains at least one of the user's group in `viewerGroups` and record is active, and record is not private (either protected or public)
- Visitors are allowed to retrieve children only of active and public entities

## Fields

- `encodedJwt`: Encoded JWT string.
- `originalRecord`: The parent entity record which contains the children that the user is querying.

## Request Path Pattern

This policy is designed to handle requests with the pattern `/entities/{entityId}/children` where the `entityId` corresponds to the parent entity in the `originalRecord`.