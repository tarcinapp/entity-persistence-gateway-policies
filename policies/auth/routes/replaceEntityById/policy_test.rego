package policies.auth.routes.replaceEntityById.policy

import data.policies.util.common.test as test

# Admin role tests - should allow all operations
test_allow_admin_global_role if {
    allow with input as produce_input_replace("tarcinapp.admin", true, {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        "_ownerGroups": ["group-1"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    }, {
        "_name": "Original Entity",
        "description": "Original Description",
        "_visibility": "public",
        "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        "_ownerGroups": ["group-1"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    })
}

test_allow_admin_records_role if {
    allow with input as produce_input_replace("tarcinapp.records.admin", true, {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "protected",
        "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        "_ownerGroups": ["group-1"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    }, {
        "_name": "Original Entity",
        "description": "Original Description",
        "_visibility": "protected",
        "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        "_ownerGroups": ["group-1"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    })
}

# Admin can modify any record regardless of ownership
test_allow_admin_global_role_other_owner if {
    allow with input as produce_input_replace("tarcinapp.admin", true, {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    }, {
        "_name": "Original Entity",
        "description": "Original Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    })
}

test_allow_admin_global_role_private_record if {
    allow with input as produce_input_replace("tarcinapp.admin", true, {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "private",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    }, {
        "_name": "Original Entity",
        "description": "Original Description",
        "_visibility": "private",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    })
}

test_allow_admin_global_role_inactive_record if {
    allow with input as produce_input_replace("tarcinapp.admin", true, {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": "2020-01-01T00:00:00Z",
        "_validUntilDateTime": "2021-01-01T00:00:00Z"
    }, {
        "_name": "Original Entity",
        "description": "Original Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": "2020-01-01T00:00:00Z",
        "_validUntilDateTime": "2021-01-01T00:00:00Z"
    })
}

test_allow_admin_entities_role_other_owner if {
    allow with input as produce_input_replace("tarcinapp.entities.admin", true, {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "private",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    }, {
        "_name": "Original Entity",
        "description": "Original Description",
        "_visibility": "private",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    })
}

test_allow_admin_entities_update_role_other_owner if {
    allow with input as produce_input_replace("tarcinapp.entities.update.admin", true, {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    }, {
        "_name": "Original Entity",
        "description": "Original Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    })
}

test_allow_admin_records_update_role_other_owner if {
    allow with input as produce_input_replace("tarcinapp.records.update.admin", true, {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "protected",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    }, {
        "_name": "Original Entity",
        "description": "Original Description",
        "_visibility": "protected",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    })
}

# Editor role tests - should allow with field restrictions
test_allow_editor_global_role_own_record if {
    allow with input as produce_input_replace("tarcinapp.editor", true, {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        "_ownerGroups": ["group-1"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null,
        "_creationDateTime": "2022-01-01T00:00:00Z",
        "_lastUpdatedDateTime": "2022-01-01T00:00:00Z",
        "_lastUpdatedBy": "original-user",
        "_createdBy": "original-user",
        "_idempotencyKey": "original-key"
    }, {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        "_ownerGroups": ["group-1"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null,
        "_creationDateTime": "2022-01-01T00:00:00Z",
        "_lastUpdatedDateTime": "2022-01-01T00:00:00Z",
        "_lastUpdatedBy": "original-user",
        "_createdBy": "original-user",
        "_idempotencyKey": "original-key"
    })
}

# Editor can modify any record regardless of ownership
test_allow_editor_global_role_other_owner if {
    allow with input as produce_input_replace("tarcinapp.editor", true, {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null,
        "_creationDateTime": "2022-01-01T00:00:00Z",
        "_lastUpdatedDateTime": "2022-01-01T00:00:00Z",
        "_lastUpdatedBy": "original-user",
        "_createdBy": "original-user",
        "_idempotencyKey": "original-key"
    }, {
        "_name": "Original Entity",
        "description": "Original Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null,
        "_creationDateTime": "2022-01-01T00:00:00Z",
        "_lastUpdatedDateTime": "2022-01-01T00:00:00Z",
        "_lastUpdatedBy": "original-user",
        "_createdBy": "original-user",
        "_idempotencyKey": "original-key"
    })
}

test_allow_editor_global_role_private_record if {
    allow with input as produce_input_replace("tarcinapp.editor", true, {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "private",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null,
        "_creationDateTime": "2022-01-01T00:00:00Z",
        "_lastUpdatedDateTime": "2022-01-01T00:00:00Z",
        "_lastUpdatedBy": "original-user",
        "_createdBy": "original-user",
        "_idempotencyKey": "original-key"
    }, {
        "_name": "Original Entity",
        "description": "Original Description",
        "_visibility": "private",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null,
        "_creationDateTime": "2022-01-01T00:00:00Z",
        "_lastUpdatedDateTime": "2022-01-01T00:00:00Z",
        "_lastUpdatedBy": "original-user",
        "_createdBy": "original-user",
        "_idempotencyKey": "original-key"
    })
}

test_allow_editor_global_role_inactive_record if {
    allow with input as produce_input_replace("tarcinapp.editor", true, {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": "2020-01-01T00:00:00Z",
        "_validUntilDateTime": "2021-01-01T00:00:00Z",
        "_creationDateTime": "2022-01-01T00:00:00Z",
        "_lastUpdatedDateTime": "2022-01-01T00:00:00Z",
        "_lastUpdatedBy": "original-user",
        "_createdBy": "original-user",
        "_idempotencyKey": "original-key"
    }, {
        "_name": "Original Entity",
        "description": "Original Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": "2020-01-01T00:00:00Z",
        "_validUntilDateTime": "2021-01-01T00:00:00Z",
        "_creationDateTime": "2022-01-01T00:00:00Z",
        "_lastUpdatedDateTime": "2022-01-01T00:00:00Z",
        "_lastUpdatedBy": "original-user",
        "_createdBy": "original-user",
        "_idempotencyKey": "original-key"
    })
}

test_allow_editor_records_role_other_owner if {
    allow with input as produce_input_replace("tarcinapp.records.editor", true, {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "protected",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null,
        "_creationDateTime": "2022-01-01T00:00:00Z",
        "_lastUpdatedDateTime": "2022-01-01T00:00:00Z",
        "_lastUpdatedBy": "original-user",
        "_createdBy": "original-user",
        "_idempotencyKey": "original-key"
    }, {
        "_name": "Original Entity",
        "description": "Original Description",
        "_visibility": "protected",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null,
        "_creationDateTime": "2022-01-01T00:00:00Z",
        "_lastUpdatedDateTime": "2022-01-01T00:00:00Z",
        "_lastUpdatedBy": "original-user",
        "_createdBy": "original-user",
        "_idempotencyKey": "original-key"
    })
}

test_allow_editor_entities_role_other_owner if {
    allow with input as produce_input_replace("tarcinapp.entities.editor", true, {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "private",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null,
        "_creationDateTime": "2022-01-01T00:00:00Z",
        "_lastUpdatedDateTime": "2022-01-01T00:00:00Z",
        "_lastUpdatedBy": "original-user",
        "_createdBy": "original-user",
        "_idempotencyKey": "original-key"
    }, {
        "_name": "Original Entity",
        "description": "Original Description",
        "_visibility": "private",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null,
        "_creationDateTime": "2022-01-01T00:00:00Z",
        "_lastUpdatedDateTime": "2022-01-01T00:00:00Z",
        "_lastUpdatedBy": "original-user",
        "_createdBy": "original-user",
        "_idempotencyKey": "original-key"
    })
}

# Editor forbidden field tests - should deny when forbidden fields have different values
test_not_allow_editor_with_different_creationDateTime if {
    not allow with input as produce_input_replace("tarcinapp.editor", true, {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null,
        "_creationDateTime": "2023-01-01T00:00:00Z"
    }, {
        "_name": "Original Entity",
        "description": "Original Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null,
        "_creationDateTime": "2022-01-01T00:00:00Z"
    })
}

test_not_allow_editor_with_different_lastUpdatedDateTime if {
    not allow with input as produce_input_replace("tarcinapp.editor", true, {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null,
        "_lastUpdatedDateTime": "2023-01-01T00:00:00Z"
    }, {
        "_name": "Original Entity",
        "description": "Original Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null,
        "_lastUpdatedDateTime": "2022-01-01T00:00:00Z"
    })
}

test_not_allow_editor_with_different_lastUpdatedBy if {
    not allow with input as produce_input_replace("tarcinapp.editor", true, {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null,
        "_lastUpdatedBy": "new-user"
    }, {
        "_name": "Original Entity",
        "description": "Original Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null,
        "_lastUpdatedBy": "original-user"
    })
}

test_not_allow_editor_with_different_createdBy if {
    not allow with input as produce_input_replace("tarcinapp.editor", true, {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null,
        "_createdBy": "new-user"
    }, {
        "_name": "Original Entity",
        "description": "Original Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null,
        "_createdBy": "original-user"
    })
}

test_not_allow_editor_with_different_idempotencyKey if {
    not allow with input as produce_input_replace("tarcinapp.editor", true, {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null,
        "_idempotencyKey": "new-key"
    }, {
        "_name": "Original Entity",
        "description": "Original Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null,
        "_idempotencyKey": "original-key"
    })
}

# Editor should allow when forbidden fields have same values
test_allow_editor_with_same_creationDateTime if {
    allow with input as produce_input_replace("tarcinapp.editor", true, {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null,
        "_creationDateTime": "2022-01-01T00:00:00Z"
    }, {
        "_name": "Original Entity",
        "description": "Original Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null,
        "_creationDateTime": "2022-01-01T00:00:00Z"
    })
}

# Member role tests - should allow only for owned records
test_allow_member_own_record if {
    allow with input as produce_input_replace("tarcinapp.member", true, {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        "_ownerGroups": ["group-1"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    }, {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        "_ownerGroups": ["group-1"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    })
}

test_allow_member_group_record_public if {
    allow with input as produce_input_replace("tarcinapp.member", true, {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user", "ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        "_ownerGroups": ["group-1"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    }, {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["group-1"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    })
}

# Negative tests
test_not_allow_member_other_user_record if {
    not allow with input as produce_input_replace("tarcinapp.member", true, {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    }, {
        "_name": "Original Entity",
        "description": "Original Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    })
}

test_not_allow_visitor_global_role if {
    not allow with input as produce_input_replace("tarcinapp.visitor", true, {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        "_ownerGroups": ["group-1"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    }, {
        "_name": "Original Entity",
        "description": "Original Description",
        "_visibility": "public",
        "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        "_ownerGroups": ["group-1"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    })
}

test_not_allow_member_without_email_verification if {
    not allow with input as produce_input_replace("tarcinapp.member", false, {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        "_ownerGroups": ["group-1"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    }, {
        "_name": "Original Entity",
        "description": "Original Description",
        "_visibility": "public",
        "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        "_ownerGroups": ["group-1"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    })
}

# Helper function
produce_input_replace(role, is_email_verified, requestPayload, originalRecord) = test_body if {
    test_body = {
        "appShortcode": "tarcinapp",
        "httpMethod": "PUT",
        "requestPath": "/generic-entities",
        "queryParams": {},
        "encodedJwt": test.produce_token({
            "sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
            "_name": "John Doe",
            "admin": true,
            "iat": 1516239022,
            "email_verified": is_email_verified,
            "groups": ["group-1", "group-2"],
            "roles": [role],
        }),
        "requestPayload": requestPayload,
        "originalRecord": originalRecord
    }
} 