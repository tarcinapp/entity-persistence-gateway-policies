package policies.auth.routes.deleteEntityById.metadata

description := `Only administrator users are allowed to delete records.`

fields := {
    "encodedJwt": "Encoded JWT string."
}