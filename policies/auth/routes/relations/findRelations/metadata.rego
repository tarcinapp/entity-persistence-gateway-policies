package policies.auth.routes.relations.findRelations.metadata

description := `This policy evaluates the user's role and email verification status to decide if a caller may perform relation search operations.

Admin and editor users are allowed to find relations.
Members and visitors can find relations if their email is verified.

The gateway is expected to narrow queries by owner/groups/visibility before calling the backend.`

fields := {"encodedJwt": "Encoded JWT string."}
