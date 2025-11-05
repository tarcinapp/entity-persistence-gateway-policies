# Create Reaction By Entity Id Policy

## Description

This policy evaluates the user's role, email verification status, request payload, and source entity visibility to determine if creation of an entity reaction is allowed. The policy defines different rules based on user roles:

- **Admin Users:** Allowed to create entity reactions if their email is verified and the payload does not contain forbidden fields.

- **Editor Users:** Allowed to create entity reactions if their email is verified and the payload does not contain forbidden fields.

- **Member Users:** Allowed to create entity reactions if all the following conditions are met:
	- The user's email is verified.
	- The payload does not contain any forbidden fields.
	- If the payload includes `_ownerGroups`, every group listed must exist in the user's token groups.
	- The source entity must be active (its `_validFromDateTime` is in the past and, if present, `_validUntilDateTime` is in the future).
	- The user must meet at least one of the following for the source entity:
		- Is listed in the source entity's `_ownerUsers`.
		- Is in a group listed in the source entity's `_ownerGroups` and the source entity is not private.
		- Is listed in the source entity's `_viewerUsers`.
		- Is in a group listed in the source entity's `_viewerGroups` and the source entity is not private.
		- The source entity is public.

## Fields

- `encodedJwt`: Encoded JWT string representing the caller.
- `requestPayload`: Request payload JSON object. Must not contain forbidden fields and may include `_ownerGroups` and `_relationMetadata`.
- `requestPayload._relationMetadata`: The parent entity metadata (used to evaluate entity visibility). Expected fields: `_id`, `_visibility`, `_validFromDateTime`, `_validUntilDateTime`, `_ownerUsers`, `_ownerGroups`, `_viewerUsers`, `_viewerGroups`, etc.
