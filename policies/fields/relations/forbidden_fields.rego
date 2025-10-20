package policies.fields.relations.policy

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
            "create": ["_createdDateTime", "_lastUpdatedDateTime", "_lastUpdatedBy", "_createdBy", "_idempotencyKey"],
            "update": ["_createdDateTime", "_lastUpdatedDateTime", "_lastUpdatedBy", "_createdBy", "_idempotencyKey"]
        }
    },
    {
        "role": "member",
        "operations": {
            "find":   ["_version", "_idempotencyKey", "_application"],
            "create": ["_createdDateTime", "_slug", "_lastUpdatedDateTime", "_lastUpdatedBy", "_createdBy", "_validFromDateTime", "_validUntilDateTime"],
            "update": ["_kind", "_slug", "_createdDateTime", "_lastUpdatedDateTime", "_lastUpdatedBy", "_createdBy", "_validFromDateTime", "_validUntilDateTime"] # valid until is added as it requires additional role to inactivate the record for members
        }
    },
    {
        "role": "visitor",
        "operations": {
            "find": []
        }
    }
]
