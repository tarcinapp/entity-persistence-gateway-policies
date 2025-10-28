package policies.auth.routes.lists.findListById.metadata

description := `This policy evaluates the user's role, email verification status and original record to decide if user retrieve the record.
- admin and editor users are always allowed to retrieve the list.
- members and visitors are allowed to retrieve lists if their email is validated. 
    Members can see the record if one of the following is true for the queried list item.
    - original record belongs to the user and is not passive ('not passive': either 'active' or 'pending')
    - original record belongs to the one of the user's groups and is not private ('not passive': either public or protected) and is not passive ('not passive': either 'active' or 'pending')
    - original record public and active
    - original record contains user's id in viewerUsers and record is active
    - original record contains at least one of the user's group in viewerGroups and record is active, and record is not private (either protected or public)
- visitors are allowed to retrieve only active and public lists`


fields := {
    "encodedJwt": "Encoded JWT string.",
    "originalRecord": "The record which the user is querying by it's id."
}