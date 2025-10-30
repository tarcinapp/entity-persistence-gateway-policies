# countListReactions policy

This directory contains the authorization policy for the `countListReactions` route.

Policy
- `policy.rego` implements role-based access control for the `count` operation on list reactions.

Rules
- Admin, Editor, Member and Visitor roles scoped for listReactions may be allowed to perform `count` when the user's email is verified.