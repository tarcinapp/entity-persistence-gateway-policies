# Create Relation Policy

## Description

This policy evaluates the user's role, email verification status, the `originalRecord` (parent list and target entity metadata), and the request payload to determine if relation creation is allowed. The policy defines different rules based on user roles:

- **Admin Users:** Admin users are allowed to create relations with no restrictions, even setting fields like `_createdBy`, `_createdDateTime`, and `_lastUpdatedDateTime`.

- **Editor Users:** Editor users are allowed to create relations with certain conditions:
    - They cannot use fields that are forbidden for editors in `policies/fields/relations/forbidden_fields.rego` (examples include `_createdDateTime`, `_createdBy`).

- **Member Users:** Member users are allowed to create relations if their email is verified and the following conditions are met:
    - Payload does not contain fields the member is forbidden to create or see (see `policies/fields/relations/forbidden_fields.rego` for authoritative lists; example forbidden fields include `_createdDateTime`, `_createdBy`, `_lastUpdatedDateTime`, `_lastUpdatedBy`).
    - Members can send `_validFromDateTime` if they have the validFrom controlling roles.
    - Members can send `_validUntilDateTime` if they have the validUntil controlling roles.
    - The caller must be the owner of the referenced list. A list belongs to the user if at least one of the following is true:
        - The user's ID is present in the list's `_ownerUsers`.
        - One of the user's groups is present in the list's `_ownerGroups` and the list `_visibility` is not private (protected or public).
    - If ownership exists via both `_ownerUsers` and `_ownerGroups`, `_ownerUsers` takes precedence.
    - The referenced list must be valid for creation (i.e., `_validFromDateTime` is not empty and in the past and `_validUntilDateTime` is empty or in the future).
    - Caller must be able to see the target entity referenced by the relation. Entity visibility to the caller is determined as follows:
        - Admin and Editor users can always retrieve the entity if their email is verified.
        - Members can create relation if the related entity is active and any of the following are true:
            - The entity belongs to the user (user's ID is in `_ownerUsers`).
            - The entity belongs to one of the user's groups, the entity `_visibility` is not private (protected or public), and is active.
            - The entity is public and active.
            - The entity's `_viewerUsers` contains the user's ID and the entity is active.
            - The entity's `_viewerGroups` contains one of the user's groups, the entity is active, and the entity is not private.
        - Visitors can only retrieve active and public entities; but visitors cannot create relations.

Notes:
- Relations only have `_validFromDateTime` and `_validUntilDateTime`; they do not include `_ownerUsers`, `_ownerGroups`, `_viewerUsers`, or `_viewerGroups`.
- The request payload will not include list and entity metadata fields. Those details are supplied in `originalRecord` as `_fromMetadata` (list metadata) and `_toMetadata` (entity metadata) and should be used for visibility and ownership checks. 

## Fields

- `encodedJwt`: Encoded JWT string.
- `requestPayload`: Request payload JSON object for the new relation.
- `originalRecord`: The original relation query result containing `fromMetadata` (list metadata) and `toMetadata` (entity metadata) used to evaluate ownership and visibility.
