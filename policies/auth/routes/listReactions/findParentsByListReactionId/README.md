# Find Parents By List Reaction Id Policy

## Description

This policy evaluates the user's role, email verification status, and the visibility of the child reaction (`originalRecord`) to decide if querying parent reactions is allowed.

- Admin users may query parent reactions if ALL are true:
	- Email is verified.
	- The caller can see the child reaction (see Child Reaction Visibility).

- Editor users may query parent reactions if ALL are true:
	- Email is verified.
	- The caller can see the child reaction (see Child Reaction Visibility).

- Member users may query parent reactions if ALL are true:
	- Email is verified.
	- The caller can see the child reaction (see Child Reaction Visibility).

- Visitor users may query parent reactions if ALL are true:
	- Email is verified.
	- The child reaction is public and active.

Child Reaction Visibility (originalRecord): at least one must hold:
- Caller owns the reaction and it is not passive (expired).
- Reaction belongs to one of the caller's groups, the reaction is not passive, and the reaction is not private.
- Reaction is public and active.
- Caller is listed in `_viewerUsers` and the reaction is active.
- Caller is in `_viewerGroups`, the reaction is not private, and the reaction is active.

## Fields

- `encodedJwt`: Encoded JWT string representing the caller.
- `originalRecord`: The child reaction record whose parents are being queried.

## Notes

This policy focuses on child reaction visibility. The gateway is responsible for shaping the query so that only parent reactions matching the caller's visibility constraints are returned. Individual parent reactions are not evaluated by this policy.
