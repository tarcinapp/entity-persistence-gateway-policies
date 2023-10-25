package policies.auth.routes.findEntityById.metadata

description := `This policy evaluates the user's role, email verification status and original record to decide if user retrieve the record.
- admin and editor users are always allowed to retrieve the entity.
- members and visitors are allowed to retrieve entities if their email is validated. 
    Members can see the record if one of the following is true for the queried record.
    - original record belongs to the user and is not passive ('not passive': either 'active' or 'pending')
    - original record belongs to the one of the user's groups and is not private ('not passive': either public or protected) and is not passive ('not passive': either 'active' or 'pending')
    - original record public and active`

fields := {
    "encodedJwt": "Encoded JWT string.",
    "originalRecord": "The record which the user is querying by it's id."
}