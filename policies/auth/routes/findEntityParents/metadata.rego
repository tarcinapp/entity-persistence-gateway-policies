package policies.auth.routes.findEntityParents.metadata

description := `This policy evaluates the user's role, email verification status and original record to decide if user can retrieve the entity's parents.
To allow caller to findParents of the entity, caller must be able to find the entity given in the originalRecord.
- admin and editor users are always allowed to retrieve the entity parents.
- members and visitors are allowed to retrieve entity parents if their email is validated. 
    Members can see the record's parents if one of the following is true for the root entity record.
    - original record belongs to the user and is not passive ('not passive': either 'active' or 'pending')
    - original record belongs to the one of the user's groups and is not private ('not passive': either public or protected) and is not passive ('not passive': either 'active' or 'pending')
    - original record public and active
    - original record contains user's id in viewerUsers and record is active
    - original record contains at least one of the user's group in viewerGroups and record is active, and record is not private (either protected or public)
- visitors are allowed to retrieve parents only of active and public entities`


fields := {
    "encodedJwt": "Encoded JWT string.",
    "originalRecord": "The root entity record whose parents the user is querying."
}