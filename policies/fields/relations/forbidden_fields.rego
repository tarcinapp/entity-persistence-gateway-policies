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
            "find":   [],
            "create": [],
            "update": []
        }
    },
    {
        "role": "visitor",
        "operations": {
            "find": []
        }
    }
]
