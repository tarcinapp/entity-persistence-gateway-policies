package policies.auth.routes.replaceEntityById.metadata

description := `This policy evaluates the user's role, email verification status, request payload and original record to decide if an user can replace the record.
- admin users are allowed to replace the record if payload satisfy 'all' of the conditions given below:
    - email must be verified
    - payload cannot contain any field that user is not allowed to see.
    - user cannot send a value different than the original record's value for fields that he is not allowed to update
- editor users are allowed to replace the record if payload satisfy 'all' of the conditions given below:
    - email must be verified
    - payload cannot contain any field that user is not allowed to see.
    - user cannot send a value different than the original record's value for fields that he is not allowed to update
- members are allowed to replace the entity if following conditions are met
    - email must be verified
    - payload cannot contain any field that user is not allowed to see.
    - user cannot send a value different than the original record's value for fields that he is not allowed to update
    - record must belong to that user. record belongs to the user if 'at least one' of the following is true
        - user's id is in ownerUsers
        - one of the user's groups is specified in the records ownerGroups field, and visibilitiy is 'not private' (it must be 'protected' or 'public').
    - payload cannot contain any field that user is not allowed to see.
    - ownerUsers contains the user's user id
    - all group names specified in ownerGroups field of the payload must be from the user's groups
    - For validFromDateTime, if user is allowed the change the value
        - validFromDateTime field of the original record must be empty
        - it must be within the last 300 seconds
    - For validUntilDateTime, if user is allowed the change the value
        - validUntilDateTime field of the original record must be empty
        - it must be within the last 300 seconds`
        
fields := {
    "encodedJwt": "Encoded JWT string.",
    "originalRecord": "The record which the user is querying by it's id.",
    "requestPayload": "Request body."
}