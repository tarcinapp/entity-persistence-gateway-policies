package policies.auth.routes.lists.findListChildren.metadata

description := `This policy evaluates the user's role, email verification status and original record to decide if user can retrieve the list's children.
To allow caller to findChildren of the list, caller must be able to find the list given in the originalRecord.
- admin and editor users are always allowed to retrieve the list children.
- members and visitors are allowed to retrieve list children if their email is validated. 
    Members can see the record's children if one of the following is true for the parent list record.
    - original record belongs to the user and is not passive ('not passive': either 'active' or 'pending')
    - original record belongs to the one of the user's groups and is not private ('not passive': either public or protected) and is not passive ('not passive': either 'active' or 'pending')
    - original record public and active
    - original record contains user's id in viewerUsers and record is active
    - original record contains at least one of the user's group in viewerGroups and record is active, and record is not private (either protected or public)
- visitors are allowed to retrieve children only of active and public lists`

fields := {
	"encodedJwt": "Encoded JWT string.",
	"originalRecord": "The parent list record which contains the children that the user is querying.",
}
