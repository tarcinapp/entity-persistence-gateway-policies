# Create Entity Policy

## Description

This policy evaluates the user's role, email verification status, and request payload to determine if entity creation is allowed. The policy defines different rules based on user roles:

- **Admin Users:** Admin users are allowed to create entities with no restrictions, even setting fields like `createdBy`, `creationDateTime`, and `lastUpdatedDateTime`.

- **Editor Users:** Editor users are allowed to create entities with certain conditions:
    - They cannot use fields like `createdBy`, `creationDateTime`, `lastUpdatedBy`, and `lastUpdatedDateTime`.

- **Member Users:** Member users are allowed to create entities if their email is verified, and they must meet specific conditions for payload fields. These conditions include:
    - Sending the `visibility` field if they have the necessary visibility-controlling roles.
    - Sending the `validFromDateTime` field if they have the appropriate roles for controlling validity starting time.
    - Sending the `validUntilDateTime` field if they have the necessary roles for controlling validity ending time.
    - They are restricted from sending the `ownerUsers` field (body manipulation may occur after authorization).
    - They cannot send fields like `creationDateTime`, `createdBy`, `lastUpdatedDateTime`, `lastUpdatedBy`.
    - Members can only specify their groups in the `ownerGroups` field.

## Fields

- `encodedJwt`: Encoded JWT string.
- `requestPayload`: Request payload JSON object.
