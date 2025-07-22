package policies.auth.routes.updateEntityById.policy

import data.policies.util.common.test as test

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

# Base payload for testing (without ownerUsers and ownerGroups for flexibility)
base_payload = {
    "_name": "Updated Entity",
    "description": "Updated description",
    "_visibility": "public",
    "_validFromDateTime": "2020-01-01T00:00:00Z",
    "_validUntilDateTime": null
}

# Base original record for testing (without ownerUsers and ownerGroups for flexibility)
base_original_record = {
    "_id": "123",
    "_name": "Original Entity",
    "description": "Original description",
    "_visibility": "public",
    "_validFromDateTime": "2020-01-01T00:00:00Z",
    "_validUntilDateTime": null,
    "_creationDateTime": "2020-01-01T00:00:00Z",
    "_lastUpdatedDateTime": "2020-01-02T00:00:00Z",
    "_lastUpdatedBy": "original-user",
    "_createdBy": "original-user"
}

# Helper function to create test input with all parameters visible in the test case
default_user_id = "ebe92b0c-bda2-49d0-99d0-feb538aa7db6"
default_group = "my-group"

default_admin_groups = [default_group]

produce_input_doc(role, is_email_verified, userGroups, payload, originalRecord) = test_body if {
    test_body = {
        "appShortcode": "tarcinapp",
        "httpMethod": "PUT",
        "requestPath": "/generic-entities/123",
        "queryParams": {},
        "encodedJwt": test.produce_token({
            "sub": default_user_id,
            "name": "John Doe",
            "admin": true,
            "iat": 1516239022,
            "email_verified": is_email_verified,
            "groups": userGroups,
            "roles": [
                "offline_access",
                "uma_authorization",
                role,
            ],
        }),
        "requestPayload": payload,
        "originalRecord": originalRecord
    }
}

# Helper function to create test input with field-level permissions
produce_input_doc_by_role_with_field_permission(role, is_email_verified, requestPayload, originalRecord, fieldPermission) = test_body if {
    test_body = {
        "appShortcode": "tarcinapp",
        "httpMethod": "PUT",
        "requestPath": "/generic-entities/123",
        "queryParams": {},
        "encodedJwt": test.produce_token({
            "sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
            "name": "John Doe",
            "admin": true,
            "iat": 1516239022,
            "email_verified": is_email_verified,
            "groups": ["my-group"],
            "roles": [
                "offline_access",
                "uma_authorization",
                role,
                fieldPermission,
            ],
        }),
        "requestPayload": requestPayload,
        "originalRecord": originalRecord
    }
}

# Helper function to create test input with custom groups for member testing
produce_input_doc_by_role_with_groups(role, is_email_verified, userGroups, requestPayload, originalRecord) = test_body if {
    test_body = {
        "appShortcode": "tarcinapp",
        "httpMethod": "PUT",
        "requestPath": "/generic-entities/123",
        "queryParams": {},
        "encodedJwt": test.produce_token({
            "sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
            "name": "John Doe",
            "admin": true,
            "iat": 1516239022,
            "email_verified": is_email_verified,
            "groups": userGroups,
            "roles": [
                "offline_access",
                "uma_authorization",
                role,
            ],
        }),
        "requestPayload": requestPayload,
        "originalRecord": originalRecord
    }
}

# ============================================================================
# ADMIN TESTS (EXAMPLES)
# ============================================================================

test_allow_to_global_admin if {
    allow with input as produce_input_doc(
        "tarcinapp.admin", true, default_admin_groups,
        {
            "_name": "Updated Entity",
            "description": "Updated description",
            "_visibility": "public",
            "_ownerUsers": [default_user_id],
            "_ownerGroups": [default_group],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": null
        },
        {
            "_id": "123",
            "_name": "Original Entity",
            "description": "Original description",
            "_visibility": "public",
            "_ownerUsers": [default_user_id],
            "_ownerGroups": [default_group],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": null,
            "_creationDateTime": "2020-01-01T00:00:00Z",
            "_lastUpdatedDateTime": "2020-01-02T00:00:00Z",
            "_lastUpdatedBy": "original-user",
            "_createdBy": "original-user"
        }
    )
}

test_not_allow_to_admin_without_email_verification if {
    not allow with input as produce_input_doc(
        "tarcinapp.admin", false, default_admin_groups,
        {
            "_name": "Updated Entity",
            "description": "Updated description",
            "_visibility": "public",
            "_ownerUsers": [default_user_id],
            "_ownerGroups": [default_group],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": null
        },
        {
            "_id": "123",
            "_name": "Original Entity",
            "description": "Original description",
            "_visibility": "public",
            "_ownerUsers": [default_user_id],
            "_ownerGroups": [default_group],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": null,
            "_creationDateTime": "2020-01-01T00:00:00Z",
            "_lastUpdatedDateTime": "2020-01-02T00:00:00Z",
            "_lastUpdatedBy": "original-user",
            "_createdBy": "original-user"
        }
    )
}

# ============================================================================
# ADMIN TESTS - EDGE CASES
# ============================================================================

# Test admin with empty payload
test_allow_to_admin_with_empty_payload if {
    allow with input as produce_input_doc(
        "tarcinapp.admin", true, default_admin_groups,
        {},
        base_original_record
    )
}

# Test admin with minimal payload
test_allow_to_admin_with_minimal_payload if {
    minimal_payload = {
        "_name": "Updated Entity"
    }
    
    allow with input as produce_input_doc(
        "tarcinapp.admin", true, default_admin_groups,
        minimal_payload,
        base_original_record
    )
}

# Test admin with all fields in payload
test_allow_to_admin_with_all_fields if {
    all_fields_payload = {
        "_id": "123",
        "_name": "Updated Entity",
        "description": "Updated description",
        "_visibility": "protected",
        "_ownerUsers": [default_user_id],
        "_ownerGroups": [default_group],
        "_validFromDateTime": "2020-01-01T00:00:00Z",
        "_validUntilDateTime": null,
        "_creationDateTime": "2020-01-01T00:00:00Z",
        "_lastUpdatedDateTime": "2020-01-02T00:00:00Z",
        "_lastUpdatedBy": "original-user",
        "_createdBy": "original-user"
    }
    
    allow with input as produce_input_doc(
        "tarcinapp.admin", true, default_admin_groups,
        all_fields_payload,
        base_original_record
    )
}

# ============================================================================
# ADMIN TESTS - DIFFERENT ORIGINAL RECORD SCENARIOS
# ============================================================================

test_allow_to_admin_with_private_original_record if {
    allow with input as produce_input_doc(
        "tarcinapp.admin", true, default_admin_groups,
        base_payload,
        {
            "_id": "123",
            "_name": "Original Entity",
            "description": "Original description",
            "_visibility": "private",
            "_ownerUsers": [default_user_id],
            "_ownerGroups": [default_group],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": null,
            "_creationDateTime": "2020-01-01T00:00:00Z",
            "_lastUpdatedDateTime": "2020-01-02T00:00:00Z",
            "_lastUpdatedBy": "original-user",
            "_createdBy": "original-user"
        }
    )
}

test_allow_to_admin_with_protected_original_record if {
    allow with input as produce_input_doc(
        "tarcinapp.admin", true, default_admin_groups,
        base_payload,
        {
            "_id": "123",
            "_name": "Original Entity",
            "description": "Original description",
            "_visibility": "protected",
            "_ownerUsers": [default_user_id],
            "_ownerGroups": [default_group],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": null,
            "_creationDateTime": "2020-01-01T00:00:00Z",
            "_lastUpdatedDateTime": "2020-01-02T00:00:00Z",
            "_lastUpdatedBy": "original-user",
            "_createdBy": "original-user"
        }
    )
}

test_allow_to_admin_with_different_owner if {
    allow with input as produce_input_doc(
        "tarcinapp.admin", true, default_admin_groups,
        base_payload,
        {
            "_id": "123",
            "_name": "Original Entity",
            "description": "Original description",
            "_visibility": "public",
            "_ownerUsers": ["different-user-id"],
            "_ownerGroups": ["different-group"],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": null,
            "_creationDateTime": "2020-01-01T00:00:00Z",
            "_lastUpdatedDateTime": "2020-01-02T00:00:00Z",
            "_lastUpdatedBy": "original-user",
            "_createdBy": "original-user"
        }
    )
}

test_allow_to_admin_with_pending_original_record if {
    allow with input as produce_input_doc(
        "tarcinapp.admin", true, default_admin_groups,
        base_payload,
        {
            "_id": "123",
            "_name": "Original Entity",
            "description": "Original description",
            "_visibility": "public",
            "_ownerUsers": [default_user_id],
            "_ownerGroups": [default_group],
            "_validFromDateTime": null,
            "_validUntilDateTime": null,
            "_creationDateTime": "2020-01-01T00:00:00Z",
            "_lastUpdatedDateTime": "2020-01-02T00:00:00Z",
            "_lastUpdatedBy": "original-user",
            "_createdBy": "original-user"
        }
    )
}

test_allow_to_admin_with_inactive_original_record if {
    allow with input as produce_input_doc(
        "tarcinapp.admin", true, default_admin_groups,
        base_payload,
        {
            "_id": "123",
            "_name": "Original Entity",
            "description": "Original description",
            "_visibility": "public",
            "_ownerUsers": [default_user_id],
            "_ownerGroups": [default_group],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": "2021-01-01T00:00:00Z",
            "_creationDateTime": "2020-01-01T00:00:00Z",
            "_lastUpdatedDateTime": "2020-01-02T00:00:00Z",
            "_lastUpdatedBy": "original-user",
            "_createdBy": "original-user"
        }
    )
}

# ============================================================================
# MEMBER TESTS (EXAMPLES)
# ============================================================================

test_allow_to_member_as_owner_user if {
    allow with input as produce_input_doc(
        "tarcinapp.member", true, ["my-group", "other-group"],
        {
            "_name": "Updated Entity",
            "description": "Updated description",
            "_visibility": "public",
            "_ownerUsers": [default_user_id],
            "_ownerGroups": ["other-group"],
            "_validUntilDateTime": null
        },
        {
            "_id": "123",
            "_name": "Original Entity",
            "description": "Original description",
            "_visibility": "public",
            "_ownerUsers": [default_user_id],
            "_ownerGroups": ["other-group"],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": null,
            "_creationDateTime": "2020-01-01T00:00:00Z",
            "_lastUpdatedDateTime": "2020-01-02T00:00:00Z",
            "_lastUpdatedBy": "original-user",
            "_createdBy": "original-user"
        }
    )
}

test_allow_to_member_as_owner_group_public if {
    allow with input as produce_input_doc(
        "tarcinapp.member", true, ["my-group"],
        {
            "_name": "Updated Entity",
            "description": "Updated description",
            "_visibility": "public",
            "_ownerUsers": ["different-user"],
            "_ownerGroups": ["my-group"],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": null
        },
        {
            "_id": "123",
            "_name": "Original Entity",
            "description": "Original description",
            "_visibility": "public",
            "_ownerUsers": ["different-user"],
            "_ownerGroups": ["my-group"],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": null,
            "_creationDateTime": "2020-01-01T00:00:00Z",
            "_lastUpdatedDateTime": "2020-01-02T00:00:00Z",
            "_lastUpdatedBy": "original-user",
            "_createdBy": "original-user"
        }
    )
}

test_allow_to_member_as_owner_group_protected if {
    allow with input as produce_input_doc(
        "tarcinapp.member", true, ["my-group"],
        {
            "_name": "Updated Entity",
            "description": "Updated description",
            "_visibility": "protected",
            "_ownerUsers": ["different-user"],
            "_ownerGroups": ["my-group"],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": null
        },
        {
            "_id": "123",
            "_name": "Original Entity",
            "description": "Original description",
            "_visibility": "protected",
            "_ownerUsers": ["different-user"],
            "_ownerGroups": ["my-group"],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": null,
            "_creationDateTime": "2020-01-01T00:00:00Z",
            "_lastUpdatedDateTime": "2020-01-02T00:00:00Z",
            "_lastUpdatedBy": "original-user",
            "_createdBy": "original-user"
        }
    )
}

test_not_allow_to_member_as_owner_group_private if {
    not allow with input as produce_input_doc(
        "tarcinapp.member", true, ["my-group"],
        {
            "_name": "Updated Entity",
            "description": "Updated description",
            "_visibility": "private",
            "_ownerUsers": ["different-user"],
            "_ownerGroups": ["my-group"],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": null
        },
        {
            "_id": "123",
            "_name": "Original Entity",
            "description": "Original description",
            "_visibility": "private",
            "_ownerUsers": ["different-user"],
            "_ownerGroups": ["my-group"],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": null,
            "_creationDateTime": "2020-01-01T00:00:00Z",
            "_lastUpdatedDateTime": "2020-01-02T00:00:00Z",
            "_lastUpdatedBy": "original-user",
            "_createdBy": "original-user"
        }
    )
}

test_not_allow_to_member_not_owner if {
    not allow with input as produce_input_doc(
        "tarcinapp.member", true, [default_group],
        {
            "_name": "Updated Entity",
            "description": "Updated description",
            "_visibility": "public",
            "_ownerUsers": ["different-user"],
            "_ownerGroups": ["different-group"],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": null
        },
        {
            "_id": "123",
            "_name": "Original Entity",
            "description": "Original description",
            "_visibility": "public",
            "_ownerUsers": ["different-user"],
            "_ownerGroups": ["different-group"],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": null,
            "_creationDateTime": "2020-01-01T00:00:00Z",
            "_lastUpdatedDateTime": "2020-01-02T00:00:00Z",
            "_lastUpdatedBy": "original-user",
            "_createdBy": "original-user"
        }
    )
}

test_allow_to_member_with_ownerUsers_in_payload if {
    allow with input as produce_input_doc(
        "tarcinapp.member", true, [default_group],
        {
            "_name": "Updated Entity",
            "description": "Updated description",
            "_visibility": "public",
            "_ownerUsers": [default_user_id],
            "_ownerGroups": ["other-group"],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": null
        },
        {
            "_id": "123",
            "_name": "Original Entity",
            "description": "Original description",
            "_visibility": "public",
            "_ownerUsers": [default_user_id],
            "_ownerGroups": ["other-group"],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": null,
            "_creationDateTime": "2020-01-01T00:00:00Z",
            "_lastUpdatedDateTime": "2020-01-02T00:00:00Z",
            "_lastUpdatedBy": "original-user",
            "_createdBy": "original-user"
        }
    )
}

test_not_allow_to_member_with_ownerUsers_not_containing_user if {
    not allow with input as produce_input_doc(
        "tarcinapp.member", true, [default_group],
        {
            "_name": "Updated Entity",
            "description": "Updated description",
            "_visibility": "public",
            "_ownerUsers": ["different-user"],
            "_ownerGroups": ["other-group"],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": null
        },
        {
            "_id": "123",
            "_name": "Original Entity",
            "description": "Original description",
            "_visibility": "public",
            "_ownerUsers": [default_user_id],
            "_ownerGroups": ["other-group"],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": null,
            "_creationDateTime": "2020-01-01T00:00:00Z",
            "_lastUpdatedDateTime": "2020-01-02T00:00:00Z",
            "_lastUpdatedBy": "original-user",
            "_createdBy": "original-user"
        }
    )
}

test_allow_to_member_with_ownerGroups_in_payload if {
    allow with input as produce_input_doc(
        "tarcinapp.member", true, ["my-group", "another-group"],
        {
            "_name": "Updated Entity",
            "description": "Updated description",
            "_visibility": "public",
            "_ownerUsers": ["different-user"],
            "_ownerGroups": ["my-group"],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": null
        },
        {
            "_id": "123",
            "_name": "Original Entity",
            "description": "Original description",
            "_visibility": "public",
            "_ownerUsers": ["different-user"],
            "_ownerGroups": ["my-group"],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": null,
            "_creationDateTime": "2020-01-01T00:00:00Z",
            "_lastUpdatedDateTime": "2020-01-02T00:00:00Z",
            "_lastUpdatedBy": "original-user",
            "_createdBy": "original-user"
        }
    )
}

test_not_allow_to_member_with_ownerGroups_not_containing_user_groups if {
    not allow with input as produce_input_doc(
        "tarcinapp.member", true, [default_group],
        {
            "_name": "Updated Entity",
            "description": "Updated description",
            "_visibility": "public",
            "_ownerUsers": ["different-user"],
            "_ownerGroups": ["different-group"],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": null
        },
        {
            "_id": "123",
            "_name": "Original Entity",
            "description": "Original description",
            "_visibility": "public",
            "_ownerUsers": [default_user_id],
            "_ownerGroups": ["my-group"],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": null,
            "_creationDateTime": "2020-01-01T00:00:00Z",
            "_lastUpdatedDateTime": "2020-01-02T00:00:00Z",
            "_lastUpdatedBy": "original-user",
            "_createdBy": "original-user"
        }
    )
}

# ============================================================================
# ADMIN TESTS - ROLE SCOPE VALIDATION
# ============================================================================

# Test that admin roles from different scopes don't work
test_not_allow_to_lists_admin if {
    not allow with input as produce_input_doc(
        "tarcinapp.lists.admin", true, default_admin_groups,
        {
            "_name": "Updated Entity",
            "description": "Updated description",
            "_visibility": "public",
            "_ownerUsers": [default_user_id],
            "_ownerGroups": [default_group],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": null
        },
        {
            "_id": "123",
            "_name": "Original Entity",
            "_visibility": "public",
            "_ownerUsers": [default_user_id],
            "_ownerGroups": [default_group],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": null,
            "_creationDateTime": "2020-01-01T00:00:00Z",
            "_lastUpdatedDateTime": "2020-01-02T00:00:00Z",
            "_lastUpdatedBy": "original-user",
            "_createdBy": "original-user"
        }
    )
}

test_not_allow_to_reactions_admin if {
    not allow with input as produce_input_doc(
        "tarcinapp.reactions.admin", true, default_admin_groups,
        {
            "_name": "Updated Entity",
            "description": "Updated description",
            "visibility": "public",
            "_ownerUsers": [default_user_id],
            "_ownerGroups": [default_group],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": null
        },
        {
            "_id": "123",
            "_name": "Original Entity",
            "description": "Original description",
            "visibility": "public",
            "_ownerUsers": [default_user_id],
            "_ownerGroups": [default_group],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": null,
            "_creationDateTime": "2020-01-01T00:00:00Z",
            "_lastUpdatedDateTime": "2020-01-02T00:00:00Z",
            "_lastUpdatedBy": "original-user",
            "_createdBy": "original-user"
        }
    )
}

test_not_allow_to_lists_update_admin if {
    not allow with input as produce_input_doc(
        "tarcinapp.lists.update.admin", true, default_admin_groups,
        {
            "_name": "Updated Entity",
            "description": "Updated description",
            "visibility": "public",
            "_ownerUsers": [default_user_id],
            "_ownerGroups": [default_group],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": null
        },
        {
            "_id": "123",
            "_name": "Original Entity",
            "description": "Original description",
            "visibility": "public",
            "_ownerUsers": [default_user_id],
            "_ownerGroups": [default_group],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": null,
            "_creationDateTime": "2020-01-01T00:00:00Z",
            "_lastUpdatedDateTime": "2020-01-02T00:00:00Z",
            "_lastUpdatedBy": "original-user",
            "_createdBy": "original-user"
        }
    )
}

test_not_allow_to_reactions_update_admin if {
    not allow with input as produce_input_doc(
        "tarcinapp.reactions.update.admin", true, default_admin_groups,
        {
            "_name": "Updated Entity",
            "description": "Updated description",
            "visibility": "public",
            "_ownerUsers": [default_user_id],
            "_ownerGroups": [default_group],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": null
        },
        {
            "_id": "123",
            "_name": "Original Entity",
            "description": "Original description",
            "visibility": "public",
            "_ownerUsers": [default_user_id],
            "_ownerGroups": [default_group],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": null,
            "_creationDateTime": "2020-01-01T00:00:00Z",
            "_lastUpdatedDateTime": "2020-01-02T00:00:00Z",
            "_lastUpdatedBy": "original-user",
            "_createdBy": "original-user"
        }
    )
}

# ============================================================================
# ADMIN TESTS - TOKEN VALIDATION
# ============================================================================

# Test admin with missing token
test_not_allow_to_admin_without_token if {
    test_body = {
        "appShortcode": "tarcinapp",
        "httpMethod": "PUT",
        "requestPath": "/generic-entities/123",
        "queryParams": {},
        "requestPayload": base_payload,
        "originalRecord": base_original_record
    }
    
    not allow with input as test_body
}

# Test admin with invalid token structure
test_not_allow_to_admin_with_invalid_token if {
    test_body = {
        "appShortcode": "tarcinapp",
        "httpMethod": "PUT",
        "requestPath": "/generic-entities/123",
        "queryParams": {},
        "encodedJwt": "invalid.jwt.token",
        "requestPayload": base_payload,
        "originalRecord": base_original_record
    }
    
    not allow with input as test_body
} 

test_not_allow_to_member_with_forbidden_update_field_changed if {
    not allow with input as produce_input_doc(
        "tarcinapp.member", true, [default_group],
        {
            "_name": "Updated Entity",
            "description": "Updated description",
            "_visibility": "public",
            "_ownerUsers": [default_user_id],
            "_ownerGroups": [default_group],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": null,
            "_creationDateTime": "2022-01-01T00:00:00Z"  # forbidden for update, changed value
        },
        {
            "_id": "123",
            "_name": "Original Entity",
            "description": "Original description",
            "_visibility": "public",
            "_ownerUsers": [default_user_id],
            "_ownerGroups": [default_group],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": null,
            "_creationDateTime": "2020-01-01T00:00:00Z",
            "_lastUpdatedDateTime": "2020-01-02T00:00:00Z",
            "_lastUpdatedBy": "original-user",
            "_createdBy": "original-user"
        }
    )
}

test_allow_to_member_with_field_level_update_role if {
    allow with input as produce_input_doc_by_role_with_field_permission(
        "tarcinapp.member", true,
        {
            "_name": "Updated Entity",
            "description": "Updated description",
            "_visibility": "public",
            "_ownerUsers": [default_user_id],
            "_ownerGroups": [default_group],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": null,
            "_creationDateTime": "2022-01-01T00:00:00Z"  # forbidden for update, changed value
        },
        {
            "_id": "123",
            "_name": "Original Entity",
            "description": "Original description",
            "_visibility": "public",
            "_ownerUsers": [default_user_id],
            "_ownerGroups": [default_group],
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": null,
            "_creationDateTime": "2020-01-01T00:00:00Z",
            "_lastUpdatedDateTime": "2020-01-02T00:00:00Z",
            "_lastUpdatedBy": "original-user",
            "_createdBy": "original-user"
        },
        "tarcinapp.entities.fields._creationDateTime.update"
    )
} 

test_not_allow_to_member_update_validFrom_no_field_role if {
    not allow with input as produce_input_doc(
        "tarcinapp.member", true, [default_group],
        {
            "_name": "Updated Entity",
            "description": "Updated description",
            "_visibility": "public",
            "_ownerUsers": [default_user_id],
            "_ownerGroups": [default_group],
            "_validFromDateTime": "2020-01-01T00:05:00Z"
        },
        {
            "_id": "123",
            "_name": "Original Entity",
            "description": "Original description",
            "_visibility": "public",
            "_ownerUsers": [default_user_id],
            "_ownerGroups": [default_group],
            "_validFromDateTime": null,
            "_validUntilDateTime": null,
            "_creationDateTime": "2020-01-01T00:00:00Z",
            "_lastUpdatedDateTime": "2020-01-02T00:00:00Z",
            "_lastUpdatedBy": "original-user",
            "_createdBy": "original-user"
        }
    )
}

test_not_allow_to_member_update_validFrom_with_role_but_original_not_null if {
    not allow with input as produce_input_doc_by_role_with_field_permission(
        "tarcinapp.member", true,
        {
            "_name": "Updated Entity",
            "description": "Updated description",
            "visibility": "public",
            "_ownerUsers": [default_user_id],
            "_ownerGroups": [default_group],
            "_validFromDateTime": "2020-01-01T00:10:00Z"
        },
        {
            "_id": "123",
            "_name": "Original Entity",
            "description": "Original description",
            "visibility": "public",
            "_ownerUsers": [default_user_id],
            "_ownerGroups": [default_group],
            "_validFromDateTime": "2020-01-01T00:05:00Z",
            "_validUntilDateTime": null,
            "_creationDateTime": "2020-01-01T00:00:00Z",
            "_lastUpdatedDateTime": "2020-01-02T00:00:00Z",
            "_lastUpdatedBy": "original-user",
            "_createdBy": "original-user"
        },
        "tarcinapp.entities.fields._validFromDateTime.update"
    )
}

test_not_allow_to_member_update_validFrom_with_role_but_value_not_in_range if {
    not allow with input as produce_input_doc_by_role_with_field_permission(
        "tarcinapp.member", true,
        {
            "_name": "Updated Entity",
            "description": "Updated description",
            "visibility": "public",
            "_ownerUsers": [default_user_id],
            "_ownerGroups": [default_group],
            "_validFromDateTime": "2000-01-01T00:00:00Z"  # way out of range
        },
        {
            "_id": "123",
            "_name": "Original Entity",
            "description": "Original description",
            "visibility": "public",
            "_ownerUsers": [default_user_id],
            "_ownerGroups": [default_group],
            "_validFromDateTime": null,
            "_validUntilDateTime": null,
            "_creationDateTime": "2020-01-01T00:00:00Z",
            "_lastUpdatedDateTime": "2020-01-02T00:00:00Z",
            "_lastUpdatedBy": "original-user",
            "_createdBy": "original-user"
        },
        "tarcinapp.entities.fields._validFromDateTime.update"
    )
}

test_allow_to_member_update_validFrom_with_role_and_value_in_range if {
    # Set up a fake 'now' and a validFrom value 100 seconds before it
    fake_now := 1700000000000000000  # 2023-11-14T12:26:40Z in nanoseconds
    validFrom := "2023-11-14T12:25:00Z"  # 100 seconds before fake_now

    allow with input as produce_input_doc_by_role_with_field_permission(
        "tarcinapp.member", true,
        {
            "_name": "Updated Entity",
            "description": "Updated description",
            "visibility": "public",
            "_ownerUsers": [default_user_id],
            "_ownerGroups": [default_group],
            "_validFromDateTime": validFrom
        },
        {
            "_id": "123",
            "_name": "Original Entity",
            "description": "Original description",
            "visibility": "public",
            "_ownerUsers": [default_user_id],
            "_ownerGroups": [default_group],
            "_validFromDateTime": null,
            "_validUntilDateTime": null,
            "_creationDateTime": "2020-01-01T00:00:00Z",
            "_lastUpdatedDateTime": "2020-01-02T00:00:00Z",
            "_lastUpdatedBy": "original-user",
            "_createdBy": "original-user"
        },
        "tarcinapp.entities.fields._validFromDateTime.update"
    ) with time.now_ns as fake_now
} 