# Find Reactions By List Id Policy

## Description

This policy decides whether a caller may list reactions attached to a specific list.

Summary:

- Admin, editor, member, and visitor roles may list list reactions when email is verified.
- The gateway is responsible for filtering reactions based on visibility rules.

## Fields

- `encodedJwt`: Encoded JWT string.
