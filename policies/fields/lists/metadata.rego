package policies.fields.lists.metadata

description := `
    This policy evaluates user's roles to decide which fields are forbidden for a specific user. Forbidden fields can be configured by modifying 
    'forbiddenFields' object.
    
    This object contains list of records which are consisting with 'role' and 'operations' field. Each record holds the list of forbidden fields
    of a specific role for each operation.

    Please note that if a field name is added to the 'find' list, then it is assumed as forbidden for 'create' and 'update' operations as well.
    No need to add the same field for create and update operations.

    Forbidden fields are never returned to the user in response body even if the user explicitly asks for them in request.

    Gateway is responsible to automatically fill those fields with the values from the original record in replace operations.

    If a field is forbidden and user uses the field in request paload, update or replace attempts will be get rejected with 401 Unauthorized error.
    
    This behavior can be tuned by changing user's roles. If user is assigned with 'manage' or 'update' roles for 
    any forbidden field, then this field is dropped from the forbidden fields list for that user. In addition to that, if user is assigned with 'find' role 
    for a specific field, we are removing that field from the list of forbbidden fields.`

fields := {
    "encodedJwt": "Encoded JWT string."
}