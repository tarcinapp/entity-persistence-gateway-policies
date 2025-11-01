# Update All Entity Reactions Policy

## Description

Authorizes bulk update (update all) for entity reactions. This mirrors the existing update-all policies for lists and entities, adapted to the entity reactions domain.

- Allowed roles: admin and editor within the reactions/entityReactions scopes (and global app admin/editor). Email must be verified.
- The request payload must not include any field that the caller is forbidden to find or update according to field-level permissions.

Specifically, allow when ALL are true:
- Caller is admin or editor as per `policies.util.entityReactions.roles` for operation `update`.
- Email verified.
- No fields from `which_fields_forbidden_for_finding` appear in payload.
- No fields from `which_fields_forbidden_for_update` appear in payload.

## Input

- appShortcode
- encodedJwt
- requestPayload: Partial update fields to be applied to matching entity reactions.
