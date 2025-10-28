package policies.auth.routes.lists.replaceListById.policy

import data.policies.util.common.test as test

# Admin role tests - should allow all operations
test_allow_admin_global_role if {
    allow with input as produce_input_replace(["tarcinapp.admin"], true, {
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

# Member tries to change visibility to 'private' for a group-owned record (should be denied)
test_not_allow_member_change_visibility_to_private_for_group_owned if {
    not allow with input as produce_input_replace(
        ["tarcinapp.member"], true,
        {
            "_name": "Test List",
            "description": "Test Description",
            "_visibility": "private",
            "_ownerUsers": ["other-user"],
            "_ownerGroups": ["group-1"],
            "_validUntilDateTime": null
        },
        {
            "_name": "Original List",
            "description": "Original Description",
            "_visibility": "protected",
            "_ownerUsers": ["other-user"],
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
# Member tries to remove a group from ownerGroups for a group-owned record (should be denied)
test_not_allow_member_remove_ownerGroup_for_group_owned if {
    not allow with input as produce_input_replace(
        ["tarcinapp.member"], true,
        {
            "_name": "Test List",
            "description": "Test Description",
            "_visibility": "protected",
            "_ownerUsers": ["other-user"],
            "_ownerGroups": [],
            "_validUntilDateTime": null
        },
        {
            "_name": "Original List",
            "description": "Original Description",
            "_visibility": "protected",
            "_ownerUsers": ["other-user"],
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

# Member tries to remove a group from ownerGroups that they do NOT belong to (should be denied)
test_not_allow_member_remove_other_group_they_do_not_belong_to if {
    not allow with input as produce_input_replace(
        ["tarcinapp.member"], true,
        {
            "_name": "Test List",
            "description": "Test Description",
            "_visibility": "protected",
            "_ownerUsers": ["other-user"],
            "_ownerGroups": ["group-1"],
            "_validUntilDateTime": null
        },
        {
            "_name": "Original List",
            "description": "Original Description",
            "_visibility": "protected",
            "_ownerUsers": ["other-user"],
            "_ownerGroups": ["group-1", "other-group"],
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
# Member tries to update an inactive record (should be denied)
test_not_allow_member_update_inactive_record if {
    not allow with input as produce_input_replace(
        ["tarcinapp.member"], true,
        {
            "_name": "Test List",
            "description": "Test Description",
            "_visibility": "public",
            "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
            "_ownerGroups": ["group-1"],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": "2021-01-01T00:00:00Z"
        },
        {
            "_name": "Original List",
            "description": "Original Description",
            "_visibility": "public",
            "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
            "_ownerGroups": ["group-1"],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": "2021-01-01T00:00:00Z"
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

# Member tries to set validFromDateTime just inside the allowed window with field-level role (should be allowed)
test_allow_member_set_validFromDateTime_inside_window_with_role if {
    now := time.now_ns() / 1000000000
    validFrom := now - 80 # 1 second inside the 300s window
    validFromStr := time.format([validFrom * 1000000000, "UTC", "RFC3339"])
    allow with input as produce_input_replace(
        ["tarcinapp.member", "tarcinapp.lists.fields._validFromDateTime.update"], true,
        {
            "_name": "Test List",
            "description": "Test Description",
            "_visibility": "public",
            "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
            "_ownerGroups": ["group-1"],
            "_validFromDateTime": validFromStr,
            "_validUntilDateTime": null
        },
        {
            "_name": "Original List",
            "description": "Original Description",
            "_visibility": "public",
            "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
            "_ownerGroups": ["group-1"],
            "_validFromDateTime": null,
            "_validUntilDateTime": null
        }
    )
}

# Member tries to set validUntilDateTime just outside the allowed window (should be denied)
test_not_allow_member_set_validUntilDateTime_outside_window if {
    now := time.now_ns() / 1000000000
    validUntil := now - 301 # 1 second outside the 300s window
    validUntilStr := time.format([validUntil * 1000000000, "UTC", "RFC3339"])
    not allow with input as produce_input_replace(
        ["tarcinapp.member", "tarcinapp.lists.fields._validUntilDateTime.update"], true,
        {
            "_name": "Test List",
            "description": "Test Description",
            "_visibility": "public",
            "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
            "_ownerGroups": ["group-1"],
            "_validUntilDateTime": validUntilStr
        },
        {
            "_name": "Original List",
            "description": "Original Description",
            "_visibility": "public",
            "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
            "_ownerGroups": ["group-1"],
            "_validUntilDateTime": null
        }
    )
}

test_allow_admin_records_role if {
    allow with input as produce_input_replace(["tarcinapp.records.admin"], true, {
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

# Admin can modify any record regardless of ownership
test_allow_admin_global_role_other_owner if {
    allow with input as produce_input_replace(["tarcinapp.admin"], true, {
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
    allow with input as produce_input_replace(["tarcinapp.admin"], true, {
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
    allow with input as produce_input_replace(["tarcinapp.admin"], true, {
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
    allow with input as produce_input_replace(["tarcinapp.lists.admin"], true, {
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
    allow with input as produce_input_replace(["tarcinapp.lists.update.admin"], true, {
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
    allow with input as produce_input_replace(["tarcinapp.records.update.admin"], true, {
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
    allow with input as produce_input_replace(["tarcinapp.editor"], true, {
        "_name": "Test List",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        "_ownerGroups": ["group-1"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null,
        "_createdDateTime": "2022-01-01T00:00:00Z",
        "_lastUpdatedDateTime": "2022-01-01T00:00:00Z",
        "_lastUpdatedBy": "original-user",
        "_createdBy": "original-user",
        "_idempotencyKey": "original-key"
    }, {
        "_name": "Test List",
        "description": "Test Description",
        "description": "Test Description",
        "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        "_ownerGroups": ["group-1"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null,
        "_createdDateTime": "2022-01-01T00:00:00Z",
        "_lastUpdatedDateTime": "2022-01-01T00:00:00Z",
        "_lastUpdatedBy": "original-user",
        "_createdBy": "original-user",
        "_idempotencyKey": "original-key"
    })
}

# Editor can modify any record regardless of ownership
test_allow_editor_global_role_other_owner if {
    allow with input as produce_input_replace(["tarcinapp.editor"], true, {
        "_name": "Test List",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null,
        "_createdDateTime": "2022-01-01T00:00:00Z",
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
        "_createdDateTime": "2022-01-01T00:00:00Z",
        "_lastUpdatedDateTime": "2022-01-01T00:00:00Z",
        "_lastUpdatedBy": "original-user",
        "_createdBy": "original-user",
        "_idempotencyKey": "original-key"
    })
}

test_allow_editor_global_role_private_record if {
    allow with input as produce_input_replace(["tarcinapp.editor"], true, {
        "_name": "Test List",
        "description": "Test Description",
        "_visibility": "private",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null,
        "_createdDateTime": "2022-01-01T00:00:00Z",
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
        "_createdDateTime": "2022-01-01T00:00:00Z",
        "_lastUpdatedDateTime": "2022-01-01T00:00:00Z",
        "_lastUpdatedBy": "original-user",
        "_createdBy": "original-user",
        "_idempotencyKey": "original-key"
    })
}

test_allow_editor_global_role_inactive_record if {
    allow with input as produce_input_replace(["tarcinapp.editor"], true, {
        "_name": "Test List",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": "2020-01-01T00:00:00Z",
        "_validUntilDateTime": "2021-01-01T00:00:00Z",
        "_createdDateTime": "2022-01-01T00:00:00Z",
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
        "_createdDateTime": "2022-01-01T00:00:00Z",
        "_lastUpdatedDateTime": "2022-01-01T00:00:00Z",
        "_lastUpdatedBy": "original-user",
        "_createdBy": "original-user",
        "_idempotencyKey": "original-key"
    })
}

test_allow_editor_records_role_other_owner if {
    allow with input as produce_input_replace(["tarcinapp.records.editor"], true, {
        "_name": "Test List",
        "description": "Test Description",
        "_visibility": "protected",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null,
        "_createdDateTime": "2022-01-01T00:00:00Z",
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
        "_createdDateTime": "2022-01-01T00:00:00Z",
        "_lastUpdatedDateTime": "2022-01-01T00:00:00Z",
        "_lastUpdatedBy": "original-user",
        "_createdBy": "original-user",
        "_idempotencyKey": "original-key"
    })
}

test_allow_editor_lists_role_other_owner if {
    allow with input as produce_input_replace(["tarcinapp.lists.editor"], true, {
        "_name": "Test List",
        "description": "Test Description",
        "_visibility": "private",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null,
        "_createdDateTime": "2022-01-01T00:00:00Z",
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
        "_createdDateTime": "2022-01-01T00:00:00Z",
        "_lastUpdatedDateTime": "2022-01-01T00:00:00Z",
        "_lastUpdatedBy": "original-user",
        "_createdBy": "original-user",
        "_idempotencyKey": "original-key"
    })
}

# Editor forbidden field tests - should deny when forbidden fields have different values
test_not_allow_editor_with_different_createdDateTime if {
    not allow with input as produce_input_replace(["tarcinapp.editor"], true, {
        "_name": "Test List",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null,
        "_createdDateTime": "2023-01-01T00:00:00Z"
    }, {
        "_name": "Original List",
        "description": "Original Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null,
        "_createdDateTime": "2022-01-01T00:00:00Z"
    })
}

test_not_allow_editor_with_different_lastUpdatedDateTime if {
    not allow with input as produce_input_replace(["tarcinapp.editor"], true, {
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
    not allow with input as produce_input_replace(["tarcinapp.editor"], true, {
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
    not allow with input as produce_input_replace(["tarcinapp.editor"], true, {
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
    not allow with input as produce_input_replace(["tarcinapp.editor"], true, {
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
test_allow_editor_with_same_createdDateTime if {
    allow with input as produce_input_replace(["tarcinapp.editor"], true, {
        "_name": "Test List",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null,
        "_createdDateTime": "2022-01-01T00:00:00Z"
    }, {
        "_name": "Original List",
        "description": "Original Description",
        "_visibility": "public",
        "_ownerUsers": ["other-user"],
        "_ownerGroups": ["other-group"],
        "_validFromDateTime": null,
        "_validUntilDateTime": null,
        "_createdDateTime": "2022-01-01T00:00:00Z"
    })
}

# Member role tests - should allow only for owned records
test_allow_member_own_record if {
    allow with input as produce_input_replace(["tarcinapp.member"], true, {
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

test_not_allow_member_modify_ownerUsers_if_record_belongs_to_his_group if {
    not allow with input as produce_input_replace(["tarcinapp.member"], true, {
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

test_allow_member_records_role_own_record if {
    allow with input as produce_input_replace(["tarcinapp.records.member"], true, {
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
    not allow with input as produce_input_replace(["tarcinapp.member"], true, {
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
    not allow with input as produce_input_replace(["tarcinapp.visitor"], true, {
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
    not allow with input as produce_input_replace(["tarcinapp.member"], false, {
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
produce_input_replace(roles, is_email_verified, requestPayload, originalRecord) = test_body if {
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
            "roles": roles,
        }),
        "requestPayload": requestPayload,
        "originalRecord": originalRecord
    }
} 

# 1. Deny: Member (owns by user ID) tries to set _validUntilDateTime to a non-null value
# User is in _ownerUsers in the original record, is a tarcinapp.member, tries to set _validUntilDateTime to a date
# Expected: Denied

test_not_allow_member_set_validUntilDateTime_without_field_role if {
    not allow with input as produce_input_replace(
        ["tarcinapp.member"], true,
        {
            "_name": "Test List",
            "description": "Test Description",
            "_visibility": "public",
            "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
            "_ownerGroups": ["group-1"],
            "_validUntilDateTime": "2024-06-01T00:00:00Z"
        },
        {
            "_name": "Original List",
            "description": "Original Description",
            "_visibility": "public",
            "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
            "_ownerGroups": ["group-1"],
            "_validUntilDateTime": null
        }
    )
}

# 2. Allow: Member with field-level update role sets _validUntilDateTime to a non-null value
# User is in _ownerUsers, is a tarcinapp.member, has tarcinapp.lists.fields._validUntilDateTime role
# Expected: Allowed

test_allow_member_set_validUntilDateTime_with_field_role if {
    now_time := time.now_ns()
    now_time_str := time.format([now_time, "UTC", "RFC3339"])

    allow with input as produce_input_replace(
        ["tarcinapp.member", "tarcinapp.lists.fields._validUntilDateTime.update"], true,
        {
            "_name": "Test List",
            "description": "Test Description",
            "_visibility": "public",
            "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
            "_ownerGroups": ["group-1"],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": now_time_str
        },
        {
            "_name": "Original List",
            "description": "Original Description",
            "_visibility": "public",
            "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
            "_ownerGroups": ["group-1"],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": null
        }
    )
}

# 3. Allow: Member owns by group (group in _ownerGroups, visibility protected)
# User is not in _ownerUsers but is in a group listed in _ownerGroups, visibility is protected
# Expected: Allowed

test_allow_member_own_by_group_protected if {
    allow with input as produce_input_replace(
        ["tarcinapp.member"], true,
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

# 4A. Additive ownerGroups: Allow if new group is user's group
# User is a member of group-1 and group-2, adds group-2 to ownerGroups
# Expected: Allowed

test_allow_member_add_ownerGroup_they_belong_to if {
    allow with input as produce_input_replace(
        ["tarcinapp.member"], true,
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
            "_visibility": "public",
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

# 4B. Additive ownerGroups: Deny if new group is not user's group
# User is a member of group-1 only, tries to add other-group
# Expected: Denied

test_not_allow_member_add_ownerGroup_they_do_not_belong_to if {
    not allow with input as produce_input_replace(
        ["tarcinapp.member"], true,
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