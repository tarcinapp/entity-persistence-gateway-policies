# Create Entity Child Policy

## Description

This policy evaluates the user's role, email verification status, original record (parent entity), and request payload to decide if entity child creation is allowed.

To allow caller to create a child of the entity, caller must meet **both** conditions:
1. **Parent Access**: Must be able to find/see the parent entity 
2. **Creation Permissions**: Must have entity creation permissions

### Role-based Permissions

- **Admin users** are allowed to create entity children under any parent entity and payload follows admin creation rules (admin users can even set `_createdBy`, `_creationDateTime` and `_lastUpdatedDateTime`)
- **Editor users** are allowed to create entity children under any parent entity and payload follows editor creation rules (editors cannot use `_creationDateTime`, `_createdBy`, `_lastUpdatedBy`, `_lastUpdatedDateTime` fields)
- **Member users** are allowed to create entity children if they can see the parent entity and payload follows member creation rules:
  - Members can send `_visibility` field if they have the visibility controlling roles
  - Members can send `_validFromDateTime` field if they have the validFrom controlling roles
  - Members can send `_validUntilDateTime` field if they have the validUntil controlling roles
  - Members can't send `_ownerUsers` field (Body manipulation may take place after authorization)
  - Members can't send `_creationDateTime` field (Body manipulation may take place after authorization)
  - Members can't send `_createdBy` field (Body manipulation may take place after authorization)
  - Members can't send `_lastUpdatedDateTime` field (Body manipulation may take place after authorization)
  - Members can't send `_lastUpdatedBy` field (Body manipulation may take place after authorization)
  - Members can only specify their groups in the `_ownerGroups` field
- **Visitors** are not allowed to create entity children

### Parent Entity Visibility Rules

Members can see the parent entity if one of the following conditions is true:
- User owns the parent entity and it is not passive (either 'active' or 'pending')
- Parent entity belongs to one of the user's groups and is not private (either public or protected) and is not passive (either 'active' or 'pending')
- Parent entity is public and active
- Parent entity contains user's id in `_viewerUsers` and record is active
- Parent entity contains at least one of the user's group in `_viewerGroups` and record is active, and record is not private (either protected or public)

## Fields

- `encodedJwt`: Encoded JWT string.
- `requestPayload`: Request payload JSON object for the new child entity.
- `originalRecord`: The parent entity record under which the child will be created.

## Request Path Pattern

This policy is designed to handle requests with the pattern `/entities/{entityId}/children` (POST method) where the `entityId` corresponds to the parent entity in the `originalRecord`.