# Delete Reactions By Entity Id Policy

## Description

Authorizes bulk delete (delete all) for entity reactions via the `/entities/{id}/reactions` endpoint. Only administrators can perform bulk deletion operations.

- Allowed roles: admin within the reactions/entityReactions scopes (and global app admin). Email must be verified.

Specifically, allow when ALL are true:
- Caller is admin as per `policies.util.entityReactions.roles` for operation `delete`.
- Email verified.

## Input

- appShortcode
- encodedJwt
- requestPath: `/entities/{entityId}/reactions`
