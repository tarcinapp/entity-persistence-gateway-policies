package policies.auth.routes.lists.findLists.metadata

description := `This policy evaluates the user's role, email verification status and request payload to decide if user can count lists.
- admin and editor users are allowed to find lists.
- members and visitors are allowed to find lists if their email is validated. 
- deciding what can a user see is handled with the query variables at the gateway`

fields := {
    "encodedJwt": "Encoded JWT string."
}