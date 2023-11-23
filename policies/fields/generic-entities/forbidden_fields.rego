package policies.fields.genericentities.policy

# admins are allowed to see and manage all fields by definition
default forbiddenFields = [
    {
        "role": "admin",
        "operations": {
            "find":   [],
            "create": [],
            "update": []
        }
    },
    {
        "role": "editor",
        "operations": {
            "find":   [],
            "create": ["creationDateTime", "lastUpdatedDateTime", "lastUpdatedBy", "createdBy", "idempotencyKey"],
            "update": ["creationDateTime", "lastUpdatedDateTime", "lastUpdatedBy", "createdBy", "idempotencyKey"],
        }
    },
    {
        "role": "member",
        "operations": {
            "find":   ["version", "idempotencyKey", "application"],
            "create": ["creationDateTime", "slug", "lastUpdatedDateTime", "lastUpdatedBy", "createdBy", "validFromDateTime", "validUntilDateTime", "ownerUsers"],
            "update": ["kind", "slug", "creationDateTime", "lastUpdatedDateTime", "lastUpdatedBy", "createdBy", "validFromDateTime", "validUntilDateTime"] # valid until is added as it requires additional role to inactivate the record for members
        }
    },
    {
        "role": "visitor",
        "operations": {
            "find": ["validFromDateTime", "validUntilDateTime", "visibility", "version", "lastUpdatedBy", "lastUpdatedDateTime", "idempotencyKey", "application"],
        }
    }
]
