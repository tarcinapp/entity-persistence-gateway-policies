# Update All Entities Policy

## Description

This policy evaluates the user's role and request payload to decide if updating entities as a whole is allowed.

## Access Control

### Allowed Roles
- **Administrators**: Users with admin roles can update all entities
- **Editors**: Users with editor roles can update all entities

### Requirements for Both Roles
1. **Email Verification**: Users must have verified email addresses
2. **Forbidden Field Validation**: The request payload cannot contain any fields that the user is not allowed to see or update
3. **Forbidden Field Value Validation**: For fields that are forbidden for updating, if they exist in the payload, they must have the same values as in the original record

### Denied Roles
- **Members**: Not allowed to perform bulk entity updates
- **Visitors**: Not allowed to perform bulk entity updates

## Role Patterns

The policy supports various role patterns for both admin and editor roles:

### Admin Role Patterns
- `tarcinapp.admin` - Global admin
- `tarcinapp.records.admin` - Records scope admin
- `tarcinapp.entities.admin` - Entities scope admin
- `tarcinapp.records.update.admin` - Records update operation admin
- `tarcinapp.entities.update.admin` - Entities update operation admin

### Editor Role Patterns
- `tarcinapp.editor` - Global editor
- `tarcinapp.records.editor` - Records scope editor
- `tarcinapp.entities.editor` - Entities scope editor
- `tarcinapp.records.update.editor` - Records update operation editor
- `tarcinapp.entities.update.editor` - Entities update operation editor

## Forbidden Fields

The policy validates that the request payload does not contain any fields that the user is not allowed to see or update. This is determined by the `forbidden_fields` policy which defines different field restrictions for different roles.

### Admin Forbidden Fields
- No forbidden fields (admins can access all fields)

### Editor Forbidden Fields
- `_creationDateTime`
- `_lastUpdatedDateTime`
- `_lastUpdatedBy`
- `_createdBy`
- `_idempotencyKey`

## Forbidden Field Value Validation

For fields that are forbidden for updating, if they exist in the request payload, the policy ensures that their values match the corresponding values in the original record. This prevents users from modifying fields they don't have permission to change while still allowing them to include these fields in their requests (e.g., for partial updates).

**Example:**
- Original record has `_creationDateTime: "2023-01-01T00:00:00Z"`
- Request payload includes `_creationDateTime: "2023-01-01T00:00:00Z"` ✅ (same value - allowed)
- Request payload includes `_creationDateTime: "2023-01-02T00:00:00Z"` ❌ (different value - denied)

## Input Fields

- `encodedJwt`: Encoded JWT string containing user authentication and authorization information
- `requestPayload`: The payload containing the entities to be updated
- `originalRecord`: The original record to be updated

## Examples

### Successful Admin Request
```json
{
  "encodedJwt": "eyJ...",
  "requestPayload": {
    "id": "123",
    "name": "Updated Entity",
    "description": "Updated description"
  },
  "originalRecord": {
    "id": "123",
    "name": "Original Entity",
    "description": "Original description",
    "_creationDateTime": "2023-01-01T00:00:00Z"
  }
}
```

### Successful Editor Request (with forbidden field same value)
```json
{
  "encodedJwt": "eyJ...",
  "requestPayload": {
    "id": "123",
    "name": "Updated Entity",
    "description": "Updated description",
    "_creationDateTime": "2023-01-01T00:00:00Z"  // Same as original
  },
  "originalRecord": {
    "id": "123",
    "name": "Original Entity",
    "description": "Original description",
    "_creationDateTime": "2023-01-01T00:00:00Z"
  }
}
```

### Failed Request (Forbidden Field Different Value)
```json
{
  "encodedJwt": "eyJ...",
  "requestPayload": {
    "id": "123",
    "name": "Updated Entity",
    "_creationDateTime": "2023-01-02T00:00:00Z"  // Different from original
  },
  "originalRecord": {
    "id": "123",
    "name": "Original Entity",
    "_creationDateTime": "2023-01-01T00:00:00Z"
  }
}
```

### Failed Request (Unverified Email)
```json
{
  "encodedJwt": "eyJ...",  // Contains email_verified: false
  "requestPayload": {
    "id": "123",
    "name": "Updated Entity"
  },
  "originalRecord": {
    "id": "123",
    "name": "Original Entity"
  }
}
```
