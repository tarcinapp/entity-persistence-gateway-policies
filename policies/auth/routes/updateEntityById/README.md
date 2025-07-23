# Update Entity by ID Policy

## Description

This policy evaluates the user's role, email verification status, request payload, and original record to decide if a user can update the record.

- **Admin users** are allowed to update the original record if the following conditions are met:
    - Email must be verified.
    - Payload cannot contain any field that the user is not allowed to see (forbidden fields for finding).
    - Payload can contain fields that the user is not allowed to update (forbidden fields for update), but their values must be the same as in the original record.
- **Editor users** can update the record if the payload satisfies all of the conditions below:
    - Email must be verified.
    - Payload cannot contain any field that the user is not allowed to see (forbidden fields for finding).
    - Payload can contain fields that the user is not allowed to update (forbidden fields for update), but their values must be the same as in the original record.
- **Members** are allowed to update the entity if the following conditions are met:
    - Email must be verified.
    - The record must belong to the user. A record belongs to the user if either of the following is true:
        - The user's ID is in `ownerUsers`.
        - One of the user's groups is specified in the record's `ownerGroups` field, and the visibility is 'not private' (it is either 'protected' or 'public').
    - Payload cannot contain any field that the user is not allowed to see (forbidden fields for finding).
    - Payload can contain fields that the user is allowed to see but not allowed to update (forbidden fields for update), but the value of such fields in the payload must be exactly the same as in the original record (including `null`). The user cannot change or clear the value of such fields.
    - If `ownerUsers` exists in the payload **and** the user was in `ownerUsers` in the original record, the payload must also contain the user ID. If the user was not in `ownerUsers` in the original record, there is no requirement to add them to `ownerUsers` in the payload.
    - All group names specified in the `ownerGroups` field of the payload must be from the user's groups.
    - If the `validFromDateTime` field exists in the payload:
        - `validFrom` field must be null in the original record.
        - `validFromDateTime` must specify a time in the last 300 seconds.
    - If the `validUntilDateTime` field exists in the payload:
        - If the original value of `_validUntilDateTime` is **not null**, member users **cannot update or clear it**.
        - If the original value is `null` and the user does **not** have the required role to update, the payload can only set `_validUntilDateTime` to `null` (it must match the original).
        - If the original value is `null` and the user **has** the required role to update, the payload may set a new value, but only if it is a timestamp within the last 300 seconds.
- **Visitors** cannot update any record.

**This ensures:**
- Users cannot see or update fields they are not permitted to.
- Fields that are visible but not updatable remain unchanged by users without the appropriate permissions.

## Fields

- `encodedJwt`: Encoded JWT string.
- `originalRecord`: The record which the user is querying by its ID.
- `requestPayload`: Request body.
