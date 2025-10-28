package policies.auth.routes.relations.deleteRelationById.metadata

description := `Only administrator users are allowed to delete relation records.`

fields := {
    "encodedJwt": "Encoded JWT string."
}
