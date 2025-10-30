package policies.auth.routes.relations.updateAllRelations.metadata

description := `Only administrator users are allowed to update relation records in bulk.`

fields := {
	"encodedJwt": "Encoded JWT string.",
	"requestPayload": "The payload containing the relations to be updated.",
}
