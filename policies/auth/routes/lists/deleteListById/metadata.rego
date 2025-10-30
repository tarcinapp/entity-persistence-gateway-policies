package policies.auth.routes.lists.deleteListById.metadata

description := `Only administrator users are allowed to delete records.`

fields := {"encodedJwt": "Encoded JWT string."}
