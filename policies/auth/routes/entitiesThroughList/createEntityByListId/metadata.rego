package policies.auth.routes.entitiesThroughList.createEntityByListId.metadata

description := `This policy enforces two checks for creating an entity under a list:
1) The caller must be permitted to create an entity (role, email verification, and forbidden-field checks).
2) The caller must be permitted to view the list identified by the operation (visibility/ownership/time checks against the provided original record).

Behavior summary:
- Admins and editors are generally allowed to create and view (subject to email-verification where required).
- Members have additional restrictions: they must not include forbidden fields in the request payload; if they include _ownerGroups, those groups must be present in the token payload; list visibility for members depends on ownership/viewer and privacy flags.
- Visitors are only allowed to see public & active records (and cannot create).

If required inputs (such as `originalRecord`) are missing, the policy will deny since ownership/visibility cannot be established.`

fields := {
    "encodedJwt": "Encoded JWT string (required by token helpers).",
    "requestPayload": "The entity creation payload (fields the caller is attempting to set).",
    "originalRecord": "The list record returned by the database (used to evaluate visibility/ownership/time)."
}
