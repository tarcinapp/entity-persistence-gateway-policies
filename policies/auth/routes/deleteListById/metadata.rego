package policies.auth.routes.deleteListById.metadata

description := `Only administrator users are allowed to delete records.`

fields := {
    "encodedJwt": "Encoded JWT string."
}