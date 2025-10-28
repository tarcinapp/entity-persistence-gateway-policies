package policies.auth.routes.relations.findRelationById.metadata

# Description mirrors other route metadata files and explains the relation-specific
# visibility semantics used by the findRelationById policy.

description := `This policy evaluates the caller's role, email verification status and the original relation record to decide if a caller may retrieve the relation by its ID.

Key differences and expectations for relations:
- Relation records do not carry ownership/viewer collections themselves. Instead the policy relies on nested metadata supplied in originalRecord:
  - _fromMetadata — metadata for the source list (used with list visibility rules).
  - _toMetadata — metadata for the target entity (used with entity visibility rules).
- A caller may see a relation only if they are allowed to see both the source and the target according to the same rules used by findListById and findEntityById.

Role summary:
- Admin and Editor users: allowed to retrieve the relation if their email is verified.
- Member users: allowed if email is verified AND the caller can see both the source and the target. "Can see" follows the same precedence and rules as lists/entities (direct owner, ownerGroups when visibility allows, public+active, viewerUsers, viewerGroups with visibility checks). Owner precedence is preserved (direct owner checks are evaluated before group membership).
- Visitor users: allowed only if email is verified AND both nested metadata entries are public and active.

Notes:
- Active/passive evaluation is performed using _validFromDateTime and _validUntilDateTime (a record is active if _validFromDateTime is present and in the past and _validUntilDateTime is not reached; passive if _validUntilDateTime exists and is in the past).
- Missing _fromMetadata or _toMetadata should be treated as denying the request because ownership/visibility cannot be established.`

fields := {
    "encodedJwt": "Encoded JWT string used to derive caller identity, roles and groups.",
    "originalRecord": "The relation retrieval result used for authorization checks. Must include `_fromMetadata` (source list metadata) and `_toMetadata` (target entity metadata)."
}
