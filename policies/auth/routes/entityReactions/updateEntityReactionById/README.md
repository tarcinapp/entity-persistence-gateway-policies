# Update Entity Reaction by ID Policy

## Description

This policy authorizes partial updates to an entity reaction. It mirrors the structure and rules of the list reaction update policy, adapted to the entity domain, and also verifies that the caller can see the related entity the reaction belongs to.

- Admin users may update when ALL are true:
  - Email is verified.
  - The payload does not contain any field the user is not allowed to see.
  - For fields the user cannot update, the payload (if present) must match the original record value.
  - Caller can see the related entity (via admin/editor/member visibility or entity being public and active).

- Editor users may update when ALL are true:
  - Email is verified.
  - The payload does not contain any field the user is not allowed to see.
  - For fields the user cannot update, the payload (if present) must match the original record value.
  - Caller can see the related entity (via editor/member visibility rules).

- Member users may update when ALL are true:
  - Email is verified.
  - The payload does not contain any field the user is not allowed to see.
  - For fields the user cannot update, the payload (if present) must match the original record value.
  - The reaction belongs to the caller, meaning at least one:
    - Caller’s user ID is in original._ownerUsers, or
    - One of caller’s groups is in original._ownerGroups AND original visibility is not private.
  - If ownership is via user ID (not via groups) and _ownerUsers is present in the payload, the caller’s user ID must be included.
  - If payload adds new groups to _ownerGroups, each new group must be among caller’s groups. Existing groups may remain even if caller does not belong to them.
  - If ownership is via groups only: cannot remove existing owner groups when _ownerGroups is present, cannot change visibility to private when _visibility is present, and cannot modify _ownerUsers when present.
  - Time fields:
    - _validFromDateTime: If original has a non-null value, it cannot change. If original is null and payload provides a value, it must be within the last 300 seconds.
    - _validUntilDateTime: If original has a non-null value, it cannot change. If original is null or missing and payload provides a value, it must be within the last 300 seconds.
  - Caller can see the related entity. A member can see the entity if at least one:
    - Caller’s ID is in entity._ownerUsers.
    - One of caller’s groups is in entity._ownerGroups and entity is not private.
    - Caller’s ID is in entity._viewerUsers and the entity is active (not expired).
    - One of caller’s groups is in entity._viewerGroups and the entity is active and not private.
    - Entity is public and active.

## Record state (pending vs expired)

- Pending: _validFromDateTime is null. Allowed to update when other conditions pass.
- Expired: _validUntilDateTime is non-null and in the past. Not allowed to update (same for replace).

## Fields

- encodedJwt: Encoded JWT string.
- originalRecord: The reaction being updated. Must include _relationMetadata holding the related entity’s visibility and ownership information.
- requestPayload: Partial update payload with fields to modify.
