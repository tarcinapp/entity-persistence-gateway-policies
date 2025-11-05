# Update Reactions By List Id Policy

## Description

Authorizes bulk update (update all) for list reactions via the `/lists/{id}/reactions` endpoint. This mirrors the `updateAllListReactions` policy, adapted to the through-route context.

- Allowed roles: admin and editor within the reactions/listReactions scopes (and global app admin/editor). Email must be verified.
- The request payload must not include any field that the caller is forbidden to find or update according to field-level permissions.

Specifically, allow when ALL are true:
- Caller is admin or editor as per `policies.util.listReactions.roles` for operation `update`.
- Email verified.
- No fields from `which_fields_forbidden_for_finding` appear in payload.
- No fields from `which_fields_forbidden_for_update` appear in payload.

## Input

- appShortcode
- encodedJwt
- requestPath: `/lists/{listId}/reactions`
- requestPayload: Partial update fields to be applied to matching list reactions.
