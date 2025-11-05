# Find Reactions By Entity Id Policy

## Description

This policy decides whether a caller may list reactions attached to a specific entity. 

Summary:

- Admin, editor, member, and visitor roles may list entity reactions when email is verified.
- The gateway is responsible for filtering reactions based on visibility rules.

## Fields

- `encodedJwt`: Encoded JWT string.
