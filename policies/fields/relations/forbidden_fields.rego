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
            "create": [],
            "update": []
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
