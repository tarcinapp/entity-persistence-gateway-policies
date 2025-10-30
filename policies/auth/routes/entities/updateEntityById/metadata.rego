package policies.auth.routes.entities.updateEntityById.metadata

description := `This policy evaluates the user's role, email verification status, request payload and original record to decide if a user can update the record.
- admin users are allowed to update the original record if following conditions are met:
    - email must be verified
    - payload cannot contain any field that user is not allowed to see (which_fields_forbidden_for_finding)
    - payload can contain fields that user is not allowed to update (which_fields_forbidden_for_update), but their values must be the same as in the original record
- editor users are allowed to update the record if payload satisfy 'all' of the conditions given below:
    - email must be verified
    - payload cannot contain any field that user is not allowed to see (which_fields_forbidden_for_finding)
    - payload can contain fields that user is not allowed to update (which_fields_forbidden_for_update), but their values must be the same as in the original record
- members are allowed to update the entity if following conditions are met
    - email must be verified
    - record must be belongs to that user. record belongs to the user if either of the following is true
        - user's id is in ownerUsers
        - one of the user's groups is specified in the records ownerGroups field, and visibilitiy is 'not private' (it is protected or public).
    - payload cannot contain any field that user is not allowed to see (which_fields_forbidden_for_finding)
    - payload can contain fields that user is not allowed to update (which_fields_forbidden_for_update), but their values must be the same as in the original record
    - if ownerUsers exists in the payload and the user was in ownerUsers in the original record, the payload must also contain the user id. If the user was not in ownerUsers in the original record, there is no requirement to add them to ownerUsers in the payload.
    - all group names specified in ownerGroups field of the payload must be from the user's groups
    - if validFromDateTime field exists in the payload
        - user must have the required roles for updating the validFromDateTime
        - validFrom field must be null in the original record
        - validFromDateTime must specify a time in last 300 seconds
    - if validUntilDateTime field exists in the payload
        - user must have the required roles for updating the validUntilDateTime
        - validUntil fields must be null in the original record
        - validUntilDateTime must specify a time in last 300 seconds

General Principles for Payload Fields:
- Visibility: The payload must not contain any field that the user is not allowed to see (forbidden-for-finding fields). Only fields the user is eligible to see may be included in the payload.
- Update Permissions: If the payload contains a field that the user is allowed to see but not allowed to update (forbidden-for-update fields), the value of that field in the payload must be exactly the same as in the original record. This applies regardless of the value (including null). The user cannot change or clear the value of such fields.

Application to _validUntilDateTime:
- If the user does not have the required role to update _validUntilDateTime:
  - The payload can only include _validUntilDateTime if its value is identical to the value in the original record (including if both are null).
  - The user cannot set a new value or clear an existing value.
- If the user has the required role to update _validUntilDateTime:
  - The payload may set a new value, but only if the original value is null and the new value is a timestamp within the last 300 seconds.

This ensures:
- Users cannot see or update fields they are not permitted to.
- Fields that are visible but not updatable remain unchanged by users without the appropriate permissions.`

fields := {
	"encodedJwt": "Encoded JWT string.",
	"originalRecord": "The record which the user is querying by it's id.",
	"requestPayload": "Request body",
}
