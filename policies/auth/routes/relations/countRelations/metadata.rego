package policies.auth.routes.relations.countRelations.metadata

description := `This policy evaluates the user's role, email verification status and request payload to decide if user can count relations.
    All roles are allowed to call count operation as long as they have their mail address validated.`

fields := {"encodedJwt": "Encoded JWT string."}
