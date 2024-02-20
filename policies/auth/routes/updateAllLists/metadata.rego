package policies.auth.routes.updateAllLists.metadata

description := `This policy evaluates the user's role to decide if updating the lists as a whole is allowed.
- Only administrators are allowed to perform this operation.`

fields := {
    "encodedJwt": "Encoded JWT string."
}