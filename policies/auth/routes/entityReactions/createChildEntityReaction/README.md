
# Create Entity Reaction Child Policy

## Description

This policy evaluates the user's role, email verification status, request payload, the visibility of the parent reaction (`originalRecord`), and the visibility of the related entity (`originalRecord._relationMetadata`) to decide if creation of a child reaction is allowed.

- Admin users may create a child reaction if ALL are true:
	- Email is verified.
	- The payload does not contain forbidden fields for reaction creation.
	- The caller can see the parent reaction (see Parent Reaction Visibility).
	- The caller can see the related entity (see Related Entity Visibility).

- Editor users may create a child reaction if ALL are true:
	- Email is verified.
	- The payload does not contain forbidden fields for reaction creation.
	- The caller can see the parent reaction (see Parent Reaction Visibility).
	- The caller can see the related entity (see Related Entity Visibility).

- Member users may create a child reaction if ALL are true:
	- Email is verified.
	- The payload does not contain forbidden fields for reaction creation.
	- If the payload includes `_ownerGroups`, each group is present in the caller's token groups.
	- The caller can see the parent reaction (see Parent Reaction Visibility).
	- The caller can see the related entity (see Related Entity Visibility).

- Visitors are not allowed to create child reactions.

Parent Reaction Visibility (originalRecord): at least one must hold (members require ACTIVE parent):
- Caller owns the reaction and it is active.
- Reaction belongs to one of the caller's groups, the reaction is not private, and it is active.
- Reaction is public and active.
- Caller is listed in `_viewerUsers` and the reaction is active.
- Caller is in `_viewerGroups`, the reaction is active, and the reaction is not private.

Related Entity Visibility (originalRecord._relationMetadata): at least one must hold (members require ACTIVE entity):
- Caller owns the entity and it is active.
- Entity belongs to one of the caller's groups, the entity is not private, and it is active.
- Entity is public and active.
- Caller is listed in `_viewerUsers` and the entity is active.
- Caller is in `_viewerGroups`, the entity is active, and the entity is not private.

## Fields

- `encodedJwt`: Encoded JWT string representing the caller.
- `originalRecord`: The parent reaction record. The related entity metadata is available at `originalRecord._relationMetadata`.
- `requestPayload`: The new child reaction payload. Must not contain forbidden fields and may include `_ownerGroups`.
