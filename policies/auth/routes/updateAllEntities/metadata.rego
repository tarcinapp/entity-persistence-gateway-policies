package policies.auth.routes.updateAllEntities.metadata

description := `This policy evaluates the user's role to decide if updating the entities as a whole is allowed.
- Only administrators are allowed to perform this operation.`

fields := {
    "encodedJwt": "Encoded JWT string."
}