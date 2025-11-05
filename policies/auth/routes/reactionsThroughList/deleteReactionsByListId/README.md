# Delete Reactions By List Id Policy

## Description

Authorizes bulk delete (delete all) for list reactions via the `/lists/{id}/reactions` endpoint. Only administrators can perform bulk deletion operations.

- Allowed roles: admin within the reactions/listReactions scopes (and global app admin). Email must be verified.

Specifically, allow when ALL are true:
- Caller is admin as per `policies.util.listReactions.roles` for operation `delete`.
- Email verified.

## Input

- appShortcode
- encodedJwt
- requestPath: `/lists/{listId}/reactions`
