package policies.auth.routes.replaceListById.policy

import data.policies.util.common.test as test

# Admin role tests - should allow all operations
test_allow_admin_global_role if {
    allow with input as produce_input_replace("tarcinapp.admin", true, {
        "_name": "Test List",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        "_ownerGroups": ["group-1"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    }, {
        "_name": "Original List",
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
        "_name": "Test List",
        "description": "Test Description",
        "_visibility": "protected",
        "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        "_ownerGroups": ["group-1"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    }, {
        "_name": "Original List",
        "description": "Original Description",
        "_visibility": "protected",
        "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        "_ownerGroups": ["group-1"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    })
}

test_allow_admin_lists_role if {
    allow with input as produce_input_replace("tarcinapp.lists.admin", true, {
        "_name": "Test List",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        "_ownerGroups": ["group-1"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    }, {
        "_name": "Original List",
        "description": "Original Description",
        "_visibility": "public",
        "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        "_ownerGroups": ["group-1"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    })
}

# Admin can modify any record regardless of ownership
test_allow_admin_global_role_other_owner if {
    allow with input as produce_input_replace("tarcinapp.admin", true, {
        "_name": "Test List",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    }, {
        "_name": "Original List",
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
        "_name": "Test List",
        "description": "Test Description",
        "_visibility": "private",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    }, {
        "_name": "Original List",
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
        "_name": "Test List",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": "2020-01-01T00:00:00Z",
        "_validUntilDateTime": "2021-01-01T00:00:00Z"
    }, {
        "_name": "Original List",
        "description": "Original Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": "2020-01-01T00:00:00Z",
        "_validUntilDateTime": "2021-01-01T00:00:00Z"
    })
}

test_allow_admin_lists_role_other_owner if {
    allow with input as produce_input_replace("tarcinapp.lists.admin", true, {
        "_name": "Test List",
        "description": "Test Description",
        "_visibility": "private",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    }, {
        "_name": "Original List",
        "description": "Original Description",
        "_visibility": "private",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    })
}

test_allow_admin_lists_update_role_other_owner if {
    allow with input as produce_input_replace("tarcinapp.lists.update.admin", true, {
        "_name": "Test List",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    }, {
        "_name": "Original List",
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
        "_name": "Test List",
        "description": "Test Description",
        "_visibility": "protected",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    }, {
        "_name": "Original List",
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
        "_name": "Test List",
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
        "_name": "Test List",
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
        "_name": "Test List",
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
        "_name": "Original List",
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
        "_name": "Test List",
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
        "_name": "Original List",
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
        "_name": "Test List",
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
        "_name": "Original List",
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
        "_name": "Test List",
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
        "_name": "Original List",
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

test_allow_editor_lists_role_other_owner if {
    allow with input as produce_input_replace("tarcinapp.lists.editor", true, {
        "_name": "Test List",
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
        "_name": "Original List",
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
        "_name": "Test List",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null,
        "_creationDateTime": "2023-01-01T00:00:00Z"
    }, {
        "_name": "Original List",
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
        "_name": "Test List",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null,
        "_lastUpdatedDateTime": "2023-01-01T00:00:00Z"
    }, {
        "_name": "Original List",
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
        "_name": "Test List",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null,
        "_lastUpdatedBy": "new-user"
    }, {
        "_name": "Original List",
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
        "_name": "Test List",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null,
        "_createdBy": "new-user"
    }, {
        "_name": "Original List",
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
        "_name": "Test List",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null,
        "_idempotencyKey": "new-key"
    }, {
        "_name": "Original List",
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
        "_name": "Test List",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null,
        "_creationDateTime": "2022-01-01T00:00:00Z"
    }, {
        "_name": "Original List",
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
        "_name": "Test List",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        "_ownerGroups": ["group-1"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    }, {
        "_name": "Test List",
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
        "_name": "Test List",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user", "ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        "_ownerGroups": ["group-1"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    }, {
        "_name": "Test List",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["group-1"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    })
}

test_allow_member_lists_role_own_record if {
    allow with input as produce_input_replace("tarcinapp.lists.member", true, {
        "_name": "Test List",
        "description": "Test Description",
        "_visibility": "private",
        "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        "_ownerGroups": ["group-1"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    }, {
        "_name": "Test List",
        "description": "Test Description",
        "_visibility": "private",
        "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        "_ownerGroups": ["group-1"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    })
}

test_allow_member_records_role_own_record if {
    allow with input as produce_input_replace("tarcinapp.records.member", true, {
        "_name": "Test List",
        "description": "Test Description",
        "_visibility": "protected",
        "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        "_ownerGroups": ["group-1"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    }, {
        "_name": "Test List",
        "description": "Test Description",
        "_visibility": "protected",
        "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        "_ownerGroups": ["group-1"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    })
}

# Negative tests
test_not_allow_member_other_user_record if {
    not allow with input as produce_input_replace("tarcinapp.member", true, {
        "_name": "Test List",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    }, {
        "_name": "Original List",
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
        "_name": "Test List",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        "_ownerGroups": ["group-1"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    }, {
        "_name": "Original List",
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
        "_name": "Test List",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        "_ownerGroups": ["group-1"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    }, {
        "_name": "Original List",
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
        "requestPath": "/lists",
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

# Enhanced group ownership tests

# Test: Member cannot modify ownerUsers if record belongs to their group
test_not_allow_member_modify_ownerUsers_if_record_belongs_to_his_group if {
    not allow with input as produce_input_replace("tarcinapp.member", true, {
        "_name": "Test List",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user", "ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        "_ownerGroups": ["group-1"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    }, {
        "_name": "Test List",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["group-1"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    })
}

# Test: Member owns by group (group in _ownerGroups, visibility protected)
# User is not in _ownerUsers but is in a group listed in _ownerGroups, visibility is protected
# Expected: Allowed
test_allow_member_own_by_group_protected if {
    allow with input as produce_input_replace(
        "tarcinapp.member", true,
        {
            "_name": "Test List",
            "description": "Test Description",
            "_visibility": "protected",
            "_ownerUsers": ["other-user"],
            "_ownerGroups": ["group-1"],
            "_validUntilDateTime": null,
            "_validFromDateTime": "2020-01-01T00:00:00Z"
        },
        {
            "_name": "Original List",
            "description": "Original Description",
            "_visibility": "protected",
            "_ownerUsers": ["other-user"],
            "_ownerGroups": ["group-1"],
            "_validUntilDateTime": null,
            "_validFromDateTime": "2020-01-01T00:00:00Z"
        }
    )
}

# Test: Additive ownerGroups - Allow if new group is user's group
# User is a member of group-1 and group-2, adds group-2 to ownerGroups
# Expected: Allowed
test_allow_member_add_ownerGroup_they_belong_to if {
    allow with input as produce_input_replace(
        "tarcinapp.member", true,
        {
            "_name": "Test List",
            "description": "Test Description",
            "_visibility": "public",
            "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
            "_ownerGroups": ["group-1", "group-2"],
            "_validUntilDateTime": null
        },
        {
            "_name": "Original List",
            "description": "Original Description",
            "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
            "_ownerGroups": ["group-1"],
            "_validUntilDateTime": null
        }
    ) with input.encodedJwt as test.produce_token({
        "sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
        "name": "John Doe",
        "admin": true,
        "iat": 1516239022,
        "email_verified": true,
        "groups": ["group-1", "group-2"],
        "roles": ["tarcinapp.member"]
    })
}

# Test: Additive ownerGroups - Deny if new group is not user's group
# User is a member of group-1 only, tries to add other-group
# Expected: Denied
test_not_allow_member_add_ownerGroup_they_do_not_belong_to if {
    not allow with input as produce_input_replace(
        "tarcinapp.member", true,
        {
            "_name": "Test List",
            "description": "Test Description",
            "_visibility": "public",
            "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
            "_ownerGroups": ["group-1", "other-group"],
            "_validUntilDateTime": null
        },
        {
            "_name": "Original List",
            "description": "Original Description",
            "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
            "_ownerGroups": ["group-1"],
            "_validUntilDateTime": null
        }
    ) with input.encodedJwt as test.produce_token({
        "sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
        "name": "John Doe",
        "admin": true,
        "iat": 1516239022,
        "email_verified": true,
        "groups": ["group-1"],
        "roles": ["tarcinapp.member"]
    })
} 