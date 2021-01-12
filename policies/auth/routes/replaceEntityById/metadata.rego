package policies.auth.routes.replaceEntityById.metadata

description := `This policy evaluates the user's role, email verification status, request payload original record to decide if user can replace the record.
- admin users are allowed to replace original record notwithstanding the payload and original record.
- editor users are allowed to replace the record if payload satisfy 'all' of the conditions given below:
    - payload cannot contain creationDateTime
    - payload cannot contain lastUpdatedDateTime
    - payload cannot contain lastUpdatedBy
    - payload cannot contain createdBy
- members are allowed to replace the entity if following conditions are met
    - email must be verified
    - record must be belongs to that user. record belongs to the user if either of the following is true
        - user's id is in ownerUsers
        - one of the user's groups is specified in the records ownerGroups field, and visibilitiy is 'not private' (it is protected or public).
    - payload does not contain creationDateTime
    - payload does not contain lastUpdatedDateTime
    - payload does not contain lastUpdatedBy
    - payload does not contain createdBy
    - kind in payload must be equal to the original record or user has the required role for updating the kind
    - visibilitiy in payload must be equal to the original record or user has the required role for updating the visibilitiy
    - ownerUsers contains the user id
    - all group names specified in ownerGroups field of the payload must be from the user's groups
    - For validFromDateTime
        - By default 
            - members cannot see the validFrom (it's a forbidden field)
            - forbidden fields are not mandatory in replace operations
            - forbidden fields are filled with the values of the original record by gateway
            - if payload contains 'validFromDateTime', replaceEntityById attempts are rejected with 401
        - if user has required role to see 'validFromDateTime' (tarcinapp.entities.fields.validFrom.find)
            - this field becomes not a forbidden field anymore, not get automatically filled by gateway
            - thus, user must send a value for this field
            - as user does not have required roles for 'updating' the validFrom the value must be equal to the one in originalRecord
        - if user has required role to manage or update 'validFromDateTime'
            - user automatically becomes able to see validFrom
            - user can specify a custom value for validFrom
            - if user specifies a date, it must be within the last 300 seconds
            - request get rejected with 401 if record already have a validFrom
    - For validUntilDateTime
        - By default
            - members cannot see the validUntil (it's a forbidden field)
            - forbidden fields are not mandatory in replace operations
            - forbidden fields are filled with the values of the original record by gateway
            - if payload contains 'validUntilDateTime', replaceEntityById attempts are rejected with 401
        - if user has required role to see 'validUntilDateTime' (tarcinapp.entities.fields.validUntil.find)
            - this field becomes not a forbidden field anymore, not get automatically filled by gateway
            - thus, user must send a value for this field
            - as user does not have required roles for 'updating' the validFrom the value must be equal to the one in originalRecord
        - if user has required role to update 'validUntilDateTime'
            - user becomes able to see validUntil
            - user can specify a custom value for validUntil
            - if user specifies a date, it must be within the last 300 seconds`

fields := {
    "encodedJwt": "Encoded JWT string.",
    "originalRecord": "The record which the user is querying by it's id.",
    "requestPayload": "The record which the user is querying by it's id."
}