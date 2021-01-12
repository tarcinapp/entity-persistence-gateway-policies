package policies.fields.genericentities.policy

description := `This policy evaluates user's roles to decide which fields are forbidden for that user.
Forbidden fields are never returned to the user in response bodes even if the user explicitly asks for them in request.
Gateway automatically fills those fields with the values from the original record in replace operations. If a field is forbidden, update or replace 
attempts get rejected with 401 Unauthorized error. This behavior can be tuned by changing user's roles. If user is assigned with 'manage' or 'update' roles for 
any forbidden field, then this field is dropped from the forbidden fields list for that user. In addition to that, if user is assigned with 'find' role 
for specific field, we are removing that field from the list of forbbidden fields.
For admin and editor users:
    - There is no forbidden fields
For members:
    ["validFromDateTime", "validUntilDateTime", "visibility"] fields are forbidden by default`

fields := {
    "encodedJwt": "Encoded JWT string."
}