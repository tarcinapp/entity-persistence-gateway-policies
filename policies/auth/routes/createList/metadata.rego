package policies.auth.routes.createList.metadata

description := `This policy evaluates the user's role, email verification status and request payload to decide if entity creation is allowed.
- admin users are allowed to create entity no matter the fields they want to use (admin users can even set createdBy, creationDateTime and lastUpdatedDateTime)
- editors users are allowed to create as long as they are not used creationDateTime, createdBy, lastUpdatedBy, lastUpdatedDateTime fields
- members are allowed to create if their email is verified and following conditions are met on payload fields.
    Members can send visibility field if he has the visibility controlling roles (see: member_roles_for_visibility)
    Members can send validFromDateTime field if he has the validFrom controlling roles (see: member_roles_for_validFrom)
    Members can send validUntilDateTime field if he has the validFrom controlling roles (see: member_roles_for_validUntil)
    Members can't send ownerUsers field (Body manipulation may take place after authorization).
    Members can't send creationDateTime field (Body manipulation may take place after authorization).
    Members can't send createdBy field (Body manipulation may take place after authorization).
    Members can't send lastUpdatedDateTime field (Body manipulation may take place after authorization).
    Members can't send lastUpdatedBy field (Body manipulation may take place after authorization).
    Members can only specify their groups in the ownerGroups field. `

fields := {
    "encodedJwt": "Encoded JWT string.",
    "requestPayload": "Request payload JSON object."
}
