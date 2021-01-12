package policies.auth.routes.updateEntityById.metadata

description := `This policy evaluates the user's role, email verification status, request payload and original record to decide if user can replace the record.
- admin users are allowed to update original record notwithstanding the payload and original record.
- editor users are allowed to update the record if payload satisfy 'all' of the conditions given below:
    - payload cannot contain creationDateTime
    - payload cannot contain lastUpdatedDateTime
    - payload cannot contain lastUpdatedBy
    - payload cannot contain createdBy
- members are allowed to update the entity if following conditions are met
    - email must be verified
    - record must be belongs to that user. record belongs to the user if either of the following is true
        - user's id is in ownerUsers
        - one of the user's groups is specified in the records ownerGroups field, and visibilitiy is 'not private' (it is protected or public).
    - payload does not contain creationDateTime
    - payload does not contain lastUpdatedDateTime
    - payload does not contain lastUpdatedBy
    - payload does not contain createdBy
    - if kind field exists in the payload user must have the required roles for updating the kind
    - if visibilitiy field exists in the payload user must have the required roles for updating the visibilitiy
    - if ownerUsers exists, it must contain the user id
    - all group names specified in ownerGroups field of the payload must be from the user's groups
    - if validFromDateTime field exists in the payload
        - user must have the required roles for updating the validFromDateTime
        - validFrom field must be null in the original record
        - validFromDateTime must specify a time in last 300 seconds
    - if validUntilDateTime field exists in the payload
        - user must have the required roles for updating the validUntilDateTime
        - validUntil fields must be null in the original record
        - validUntilDateTime must specify a time in last 300 seconds

fields := {
    "encodedJwt": "Encoded JWT string.",
    "originalRecord": "The record which the user is querying by it's id.",
    "requestPayload": "Request body"
}