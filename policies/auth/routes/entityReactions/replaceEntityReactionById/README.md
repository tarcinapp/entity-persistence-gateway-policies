# Replace Entity Reaction by ID Policy

## Description

This policy evaluates the user's role, email verification status, request payload, and original record to decide if a user can replace an entity reaction. The policy also verifies that the user can see the related entity that the reaction belongs to.

- Admin users are allowed to replace the reaction if the payload satisfies 'all' of the conditions given below:
  - Email must be verified.
  - The payload cannot contain any field that the user is not allowed to see.
  - The user cannot send a value different from the original record's value for fields that they are not allowed to update.
  - The user must be able to see the related entity (through admin access, editor access, member access with appropriate visibility, or public active entity).

- Editor users are allowed to replace the reaction if the payload satisfies 'all' of the conditions given below:
  - Email must be verified.
  - The payload cannot contain any field that the user is not allowed to see.
  - The user cannot send a value different from the original record's value for fields that they are not allowed to update.
  - The user must be able to see the related entity (through editor access or member access with appropriate visibility).

- Members are allowed to replace the reaction if the following conditions are met:
  - Email must be verified.
  - The payload cannot contain any field that the user is not allowed to see.
  - The user cannot send a value different from the original record's value for fields that they are not allowed to update.
  - The reaction must belong to that user. A reaction belongs to the user if 'at least one' of the following is true:
    - User's ID is in ownerUsers of the original record.
    - One of the user's groups is specified in the original record's ownerGroups field, and visibility is 'not private' (it must be either 'protected' or 'public').
  - Note: If a user owns the reaction through both ownerUsers and ownerGroups, the policy treats this as ownership through ownerUsers.
  - The ownerUsers field of the request payload contains the user's user ID if the user owns the reaction through user ID ownership - not through group ownership.
  - If the payload adds any new group(s) to ownerGroups (i.e., groups not present in the original record), those new group(s) must be from the user's groups. The user cannot add a group to a record that they are not a member of. Existing groups in the original record that the user is not a member of may remain.
  - If the user owns the reaction through group ownership only (i.e., the user's ID is not in ownerUsers of the original record, but at least one of the user's groups is in ownerGroups and the record is not private), the following restrictions apply:
    - Cannot remove existing groups from ownerGroups.
    - Cannot change visibility to 'private'.
    - Cannot modify the ownerUsers field.
  - The reaction must not be passive (validUntilDateTime must be null or in the future).
  - For validFromDateTime, if the user is allowed to change the value:
    - The validFromDateTime field of the original record must be empty.
    - It must be within the last 300 seconds.
  - For validUntilDateTime, if the user is allowed to change the value:
    - The validUntilDateTime field of the original record must be empty.
    - It must be within the last 300 seconds.
  - The user must be able to see the related entity. A member can see the entity if 'at least one' of the following is true:
    - User's ID is in ownerUsers of the related entity.
    - One of the user's groups is in ownerGroups of the related entity, and the entity is not private.
    - User's ID is in viewerUsers of the related entity, and the entity is not passive.
    - One of the user's groups is in viewerGroups of the related entity, and the entity is not private and not passive.
    - The entity is public and active.

## Fields

- `encodedJwt`: Encoded JWT string.
- `originalRecord`: The reaction record which the user is attempting to replace, including `_relationMetadata` that contains the related entity's visibility and ownership information.
- `requestPayload`: Request body containing the updated reaction data.

