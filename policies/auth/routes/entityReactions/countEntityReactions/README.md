# countEntityReactions policy

This directory contains the authorization policy for the `countEntityReactions` route.

Policy
- `policy.rego` implements role-based access control for the `count` operation on entity reactions.

Rules
- Admin, Editor, Member and Visitor roles scoped for entityReactions may be allowed to perform `count` when the user's email is verified.

Tests
- Unit tests for this policy are in `policy_test.rego` in the same directory. The tests exercise the baseline role/email verification cases.

See also
- The policy follows the same structure as other `count*` policies in `policies/auth/routes/*/count*/`.
