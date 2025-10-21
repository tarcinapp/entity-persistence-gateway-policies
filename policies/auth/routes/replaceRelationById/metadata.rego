package policies.auth.routes.replaceRelationById.metadata

description := `This policy evaluates the caller's role, email verification status, the request payload and the original relation record (including nested list and entity metadata) to determine whether the caller may replace the relation by its id.

Key points:
- Relations do not have owner/viewer lists themselves. Ownership and visibility checks are performed against the nested metadata supplied in 'originalRecord':
  - '_fromMetadata' — the referenced list's metadata (used for ownership and list validity checks)
  - '_toMetadata' — the referenced entity's metadata (used to check whether the caller can see the target entity)
- Admins and Editors are allowed to replace relations when email is verified, request payload does not include fields the caller cannot see, and forbidden-for-update fields are not changed. Editors are still denied when forbidden update fields differ from the original unless the value is the same.
- Members may replace relations only if email is verified, they own the referenced list, they can see both the list and the entity according to the visibility rules used by lists/entities, relation ids are unchanged, and they respect field-level update controls for '_validFromDateTime' and '_validUntilDateTime'. Members cannot update passive relations.
- Visitors cannot replace relations.

Time semantics:
- Active: '_validFromDateTime' exists and is in the past and record is not passive.
- Passive: '_validUntilDateTime' exists and is in the past.
- Pending: '_validFromDateTime' is null.

Field-level notes:
- The policy consults 'policies/fields/relations/forbidden_fields.rego' to determine which fields the caller can find/create/update/manage. If a forbidden-for-update field had a value in the original record, the caller must provide the same value in the request payload (they cannot remove, null, or change that value) unless a field-level role allows the update.

Missing nested metadata should be treated as denial because ownership/visibility cannot be established.`

fields := {
    "encodedJwt": "Encoded JWT string used to derive caller identity, roles and groups.",
    "requestPayload": "Request payload JSON object for the replace-by-id operation (relation fields and any allowed metadata overrides).",
    "originalRecord": "The existing relation record returned by the database including `_fromMetadata` (list metadata) and `_toMetadata` (entity metadata) used for authorization checks."
}
