# Update Entities By List Id Policy

## Description

Authorizes bulk update (update all) for entities via the `/lists/{id}/entities` endpoint. 

- Allowed roles: admin and editor within the entities scope (and global app admin/editor). Email must be verified.
- The request payload must not include any field that the caller is forbidden to find or update according to field-level permissions.

Specifically, allow when ALL are true:
- Caller is admin or editor as per `policies.util.entities.roles` for operation `update`.
- Email verified.
- No forbidden fields (from find or update operations) appear in payload.

## Input

- appShortcode
- encodedJwt
- requestPath: `/lists/{listId}/entities`
- requestPayload: Partial update fields to be applied to matching entities.
