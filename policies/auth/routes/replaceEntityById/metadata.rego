package policies.auth.routes.replaceEntityById.metadata

description := `This policy evaluates the user's role, email verification status, request payload, and original record to decide if a user can replace the record.

- Admin users are allowed to replace the record if the payload satisfies 'all' of the conditions given below:
  - Email must be verified.
  - The payload cannot contain any field that the user is not allowed to see.
  - The user cannot send a value different from the original record's value for fields that they are not allowed to update.

- Editor users are allowed to replace the record if the payload satisfies 'all' of the conditions given below:
  - Email must be verified.
  - The payload cannot contain any field that the user is not allowed to see.
  - The user cannot send a value different from the original record's value for fields that they are not allowed to update.

- Members are allowed to replace the entity if the following conditions are met:
  - Email must be verified.
  - The payload cannot contain any field that the user is not allowed to see.
  - The user cannot send a value different from the original record's value for fields that they are not allowed to update.
  - The record must belong to that user. A record belongs to the user if 'at least one' of the following is true:
    - User's ID is in ownerUsers of the original record.
    - One of the user's groups is specified in the original record's ownerGroups field, and visibility is 'not private' (it must be either 'protected' or 'public').
  - The ownerUsers field of the request payload contains the user's user ID.
  - If the payload adds any new group(s) to ownerGroups (i.e., groups not present in the original record), those new group(s) must be from the user's groups. The user cannot add a group to a record that they are not a member of. Existing groups in the original record that the user is not a member of may remain.
  - If the user owns the record through group ownership only (i.e., the user's ID is not in ownerUsers of the original record, but at least one of the user's groups is in ownerGroups and the record is not private), the following restrictions apply:
    - Cannot remove existing groups from ownerGroups.
    - Cannot change visibility to 'private'.
    - Cannot modify the ownerUsers field.
  - For validFromDateTime, if the user is allowed to change the value:
    - The validFromDateTime field of the original record must be empty.
    - It must be within the last 300 seconds.
  - For validUntilDateTime, if the user is allowed to change the value:
    - The validUntilDateTime field of the original record must be empty.
    - It must be within the last 300 seconds.`
        
fields := {
    "encodedJwt": "Encoded JWT string.",
    "originalRecord": "The record which the user is querying by it's id.",
    "requestPayload": "Request body."
}