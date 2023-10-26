# Update Entity by ID Policy

## Description

This policy evaluates the user's role, email verification status, request payload, and original record to decide if a user can update the record.

- Admin users are allowed to update the original record irrespective of the payload and the original record.
- Editor users can update the record if the payload satisfies all of the conditions below:
    - Email must be verified.
    - Payload cannot contain `creationDateTime`.
    - Payload cannot contain any field that the user is not allowed to see or update.
- Members are allowed to update the entity if the following conditions are met:
    - Email must be verified.
    - The record must belong to the user. A record belongs to the user if either of the following is true:
        - The user's ID is in `ownerUsers`.
        - One of the user's groups is specified in the record's `ownerGroups` field, and the visibility is 'not private' (it is either 'protected' or 'public').
    - Payload does not contain `creationDateTime`.
    - Payload does not contain `lastUpdatedDateTime`.
    - Payload does not contain `lastUpdatedBy`.
    - Payload does not contain `createdBy`.
    - If the `kind` field exists in the payload, the user must have the required roles for updating the `kind`.
    - If the `visibility` field exists in the payload, the user must have the required roles for updating the visibility.
    - If `ownerUsers` exist, it must contain the user ID.
    - All group names specified in the `ownerGroups` field of the payload must be from the user's groups.
    - If the `validFromDateTime` field exists in the payload:
        - The user must have the required roles for updating the `validFromDateTime`.
        - `validFrom` field must be null in the original record.
        - `validFromDateTime` must specify a time in the last 300 seconds.
    - If the `validUntilDateTime` field exists in the payload:
        - The user must have the required roles for updating the `validUntilDateTime`.
        - `validUntil` fields must be null in the original record.
        - `validUntilDateTime` must specify a time in the last 300 seconds.

## Fields

- `encodedJwt`: Encoded JWT string.
- `originalRecord`: The record which the user is querying by its ID.
- `requestPayload`: Request body.
