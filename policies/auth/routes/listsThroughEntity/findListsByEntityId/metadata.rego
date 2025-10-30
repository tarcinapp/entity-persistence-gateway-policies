package policies.auth.routes.listsThroughEntity.findListsByEntityId.metadata

description := `This policy evaluates the caller's role, email verification status and the provided original entity record to decide if the caller may query lists through an entity id.

- The caller must be permitted to find lists (same logic as the 'findLists' policy):
  - admin and editor users are allowed to find lists.
  - members and visitors are allowed to find lists if their email is validated.
- The caller must also be permitted to see the provided 'originalRecord' (same logic as 'findEntityById'):
  - admin and editor users are always allowed to retrieve the entity.
  - members can view the record if one of the following is true for the queried record:
    - the original record belongs to the user and is not passive (either 'active' or 'pending').
    - the original record belongs to one of the user's groups and is not private (either 'public' or 'protected') and is not passive (either 'active' or 'pending').
    - the original record is public and active.
    - the original record contains the user's id in 'viewerUsers' and the record is active.
    - the original record contains at least one of the user's groups in 'viewerGroups', the record is active, and the record is not private (either 'public' or 'protected').
  - visitors are allowed to retrieve only active and public entities.

Missing 'originalRecord' should be treated as denial because visibility cannot be established.`

fields := {
	"encodedJwt": "Encoded JWT string.",
	"appShortcode": "Application shortcode used by the role-matching helpers (e.g. used in role regex patterns).",
	"originalRecord": "The entity record being queried (its metadata is used for visibility checks).",
}
