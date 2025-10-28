package policies.auth.routes.relations.createRelation.metadata

description := `This policy evaluates the caller's role, email verification status, the request payload and the original record (list and entity metadata) to decide if a relation creation request is allowed.

Relation creation follows similar principles to entity and list creation but with the following differences:
- Relations only have _validFromDateTime and _validUntilDateTime. They do not have _ownerUsers, _ownerGroups, _viewerUsers or _viewerGroups.
- The caller must be the owner of the referenced list AND must be able to see the targeted entity.

Role specific notes:
- Admin users: Email must be verified. Admins are not subject to forbidden create fields for relations by default.
- Editor users: Email must be verified and payload must not contain fields the editor is not allowed to create (see relations forbidden fields).
- Member users: Email must be verified, payload must not contain fields they are not allowed to create, and the referenced list must belong to the user (either via _ownerUsers or _ownerGroups when visibility allows). The list must also be active/valid (validFrom/validUntil checks).

Entity visibility rules are the same as in findEntityById: admins and editors can always retrieve entities; members and visitors require verified email and additional checks (membership, viewer lists, public visibility, and validity). Visitors cannot create relations.

The request payload will not include full list and entity details. Those are provided in the originalRecord as fromMetadata and toMetadata and should be used for ownership and visibility checks.`

fields := {
    "encodedJwt": "Encoded JWT string.",
    "requestPayload": "Request payload JSON object for the new relation.",
    "originalRecord": "The original relation query result including `fromMetadata` (list metadata) and `toMetadata` (entity metadata) used for authorization checks."
}
