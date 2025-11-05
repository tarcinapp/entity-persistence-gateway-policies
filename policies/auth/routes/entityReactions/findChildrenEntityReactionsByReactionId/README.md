# Find Children Entity Reactions By Reaction Id Policy

## Description

This policy evaluates the user's role, email verification status, and the visibility of the parent reaction (`originalRecord`) to decide if querying child reactions is allowed.

- Admin users may query child reactions if ALL are true:
	- Email is verified.
	- The caller can see the parent reaction (see Parent Reaction Visibility).

- Editor users may query child reactions if ALL are true:
	- Email is verified.
	- The caller can see the parent reaction (see Parent Reaction Visibility).

- Member users may query child reactions if ALL are true:
	- Email is verified.
	- The caller can see the parent reaction (see Parent Reaction Visibility).

- Visitor users may query child reactions if ALL are true:
	- Email is verified.
	- The parent reaction is public and active.

Parent Reaction Visibility (originalRecord) — at least one must hold:
- Caller owns the reaction and it is not passive (expired).
- Reaction belongs to one of the caller's groups, the reaction is not passive, and the reaction is not private.
- Reaction is public and active.
- Caller is listed in `_viewerUsers` and the reaction is active.
- Caller is in `_viewerGroups`, the reaction is not private, and the reaction is active.

## Fields

- `encodedJwt`: Encoded JWT string representing the caller.
- `originalRecord`: The parent reaction record whose children are being queried.

## Notes

This policy focuses on parent reaction visibility. The gateway is responsible for shaping the query so that only child reactions matching the caller's visibility constraints are returned. Individual child reactions are not evaluated by this policy.
