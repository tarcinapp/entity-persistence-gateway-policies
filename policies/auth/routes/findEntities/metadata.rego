package policies.auth.routes.findEntities.metadata

description := `This policy evaluates the user's role, email verification status and request payload to decide if user can count entities.
- admin and editor users are allowed to find entities.
- members and visitors are allowed to find entities if their email is validated. `

fields := {
    "encodedJwt": "Encoded JWT string."
}