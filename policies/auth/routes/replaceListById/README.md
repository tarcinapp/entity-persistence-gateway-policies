# Replace List by ID Policy

## Description

This policy evaluates the user's role, email verification status, request payload, and original record to decide if a user can replace the record.

- Admin users are allowed to replace the record if the payload satisfies 'all' of the conditions given below:
  - Email must be verified.
  - The payload cannot contain any field that the user is not allowed to see.
  - The user cannot send a value different from the original record's value for fields that they are not allowed to update.

- Editor users are allowed to replace the record if the payload satisfies 'all' of the conditions given below:
  - Email must be verified.
  - The payload cannot contain any field that the user is not allowed to see.
  - The user cannot send a value different from the original record's value for fields that they are not allowed to update.

- Members are allowed to replace the list if the following conditions are met:
  - Email must be verified.
  - The payload cannot contain any field that the user is not allowed to see.
  - The user cannot send a value different from the original record's value for fields that they are not allowed to update.
  - The record must belong to that user. A record belongs to the user if 'at least one' of the following is true:
    - User's ID is in ownerUsers of the original record.
    - One of the user's groups is specified in the original record's ownerGroups field, and visibility is 'not private' (it must be either 'protected' or 'public').
  - The ownerUsers field of the request payload contains the user's user ID.
  - All group names specified in the ownerGroups field of the request payload must be from the user's groups.
  - For validFromDateTime, if the user is allowed to change the value:
    - The validFromDateTime field of the original record must be empty.
    - It must be within the last 300 seconds.
  - For validUntilDateTime, if the user is allowed to change the value:
    - The validUntilDateTime field of the original record must be empty.
    - It must be within the last 300 seconds.

## Fields

- `encodedJwt`: Encoded JWT string.
- `originalRecord`: The record which the user is querying by its ID.
- `requestPayload`: Request body.
