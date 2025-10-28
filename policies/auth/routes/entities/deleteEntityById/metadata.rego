package policies.auth.routes.entities.deleteEntityById.metadata

description := `Only administrator users are allowed to delete records.`

fields := {
    "encodedJwt": "Encoded JWT string."
}