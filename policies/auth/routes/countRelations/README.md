```markdown
# Count Relations Policy

## Description

This policy evaluates the user's role, email verification status, and request payload to determine whether the user can count relations. All roles are allowed to call the count operation as long as they have their email address validated.

## Fields

- `encodedJwt`: Encoded JWT string.

```
