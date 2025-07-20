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

# Helper function to create payload with specific ownership
produce_payload_with_ownership(ownerUsers, ownerGroups) = payload if {
    payload := object.union(base_payload, {
        "_ownerUsers": ownerUsers,
        "_ownerGroups": ownerGroups
    })
}

# Helper function to create original record with specific ownership
produce_original_record_with_ownership(ownerUsers, ownerGroups) = original_record if {
    original_record := object.union(base_original_record, {
        "_ownerUsers": ownerUsers,
        "_ownerGroups": ownerGroups
    })
}

# Helper function to create test input for admin with default ownership
produce_input_doc_by_role(role, is_email_verified) = test_body if {
    default_ownerUsers = ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"]
    default_ownerGroups = ["my-group"]
    test_body := produce_input_doc_by_role_with_payload(role, is_email_verified, 
        produce_payload_with_ownership(default_ownerUsers, default_ownerGroups), 
        produce_original_record_with_ownership(default_ownerUsers, default_ownerGroups)
    )
}

# Helper function to create test input with custom payload and original record
produce_input_doc_by_role_with_payload(role, is_email_verified, requestPayload, originalRecord) = test_body if {
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
            ],
        }),
        "requestPayload": requestPayload,
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
# ADMIN TESTS - POSITIVE CASES
# ============================================================================

# Test global admin role
test_allow_to_global_admin if {
    allow with input as produce_input_doc_by_role("tarcinapp.admin", true)
}

# Test records scope admin role
test_allow_to_records_admin if {
    allow with input as produce_input_doc_by_role("tarcinapp.records.admin", true)
}

# Test entities scope admin role
test_allow_to_entities_admin if {
    allow with input as produce_input_doc_by_role("tarcinapp.entities.admin", true)
}

# Test records update operation admin role
test_allow_to_records_update_admin if {
    allow with input as produce_input_doc_by_role("tarcinapp.records.update.admin", true)
}

# Test entities update operation admin role
test_allow_to_entities_update_admin if {
    allow with input as produce_input_doc_by_role("tarcinapp.entities.update.admin", true)
}

# ============================================================================
# ADMIN TESTS - NEGATIVE CASES
# ============================================================================

# Test admin without email verification
test_not_allow_to_admin_without_email_verification if {
    not allow with input as produce_input_doc_by_role("tarcinapp.admin", false)
}

# ============================================================================
# ADMIN TESTS - EDGE CASES
# ============================================================================

# Test admin with empty payload
test_allow_to_admin_with_empty_payload if {
    allow with input as produce_input_doc_by_role_with_payload("tarcinapp.admin", true, {}, base_original_record)
}

# Test admin with minimal payload
test_allow_to_admin_with_minimal_payload if {
    minimal_payload = {
        "_name": "Updated Entity"
    }
    
    allow with input as produce_input_doc_by_role_with_payload("tarcinapp.admin", true, minimal_payload, base_original_record)
}

# Test admin with all fields in payload
test_allow_to_admin_with_all_fields if {
    all_fields_payload = {
        "_id": "123",
        "_name": "Updated Entity",
        "description": "Updated description",
        "_visibility": "protected",
        "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        "_ownerGroups": ["my-group"],
        "_validFromDateTime": "2020-01-01T00:00:00Z",
        "_validUntilDateTime": null,
        "_creationDateTime": "2020-01-01T00:00:00Z",
        "_lastUpdatedDateTime": "2020-01-02T00:00:00Z",
        "_lastUpdatedBy": "original-user",
        "_createdBy": "original-user"
    }
    
    allow with input as produce_input_doc_by_role_with_payload("tarcinapp.admin", true, all_fields_payload, base_original_record)
}

# ============================================================================
# ADMIN TESTS - DIFFERENT ORIGINAL RECORD SCENARIOS
# ============================================================================

# Test admin with private original record
test_allow_to_admin_with_private_original_record if {
    private_original_record := object.union(base_original_record, {
        "_visibility": "private"
    })
    
    allow with input as produce_input_doc_by_role_with_payload("tarcinapp.admin", true, base_payload, private_original_record)
}

# Test admin with protected original record
test_allow_to_admin_with_protected_original_record if {
    protected_original_record := object.union(base_original_record, {
        "_visibility": "protected"
    })
    
    allow with input as produce_input_doc_by_role_with_payload("tarcinapp.admin", true, base_payload, protected_original_record)
}

# Test admin with different owner in original record
test_allow_to_admin_with_different_owner if {
    different_owner_original_record := produce_original_record_with_ownership(["different-user-id"], ["different-group"])
    
    allow with input as produce_input_doc_by_role_with_payload("tarcinapp.admin", true, base_payload, different_owner_original_record)
}

# Test admin with pending original record (no validFromDateTime)
test_allow_to_admin_with_pending_original_record if {
    pending_original_record := object.union(base_original_record, {
        "_validFromDateTime": null
    })
    
    allow with input as produce_input_doc_by_role_with_payload("tarcinapp.admin", true, base_payload, pending_original_record)
}

# Test admin with inactive original record (has validUntilDateTime)
test_allow_to_admin_with_inactive_original_record if {
    inactive_original_record := object.union(base_original_record, {
        "_validUntilDateTime": "2021-01-01T00:00:00Z"
    })
    
    allow with input as produce_input_doc_by_role_with_payload("tarcinapp.admin", true, base_payload, inactive_original_record)
}

# ============================================================================
# MEMBER TESTS - EXAMPLE CASES (Demonstrating Ownership Flexibility)
# ============================================================================

# Test member with user as owner (user ID in ownerUsers)
test_allow_to_member_as_owner_user if {
    user_id = "ebe92b0c-bda2-49d0-99d0-feb538aa7db6"
    ownerUsers = [user_id]
    ownerGroups = ["other-group"]
    
    payload := produce_payload_with_ownership(ownerUsers, ownerGroups)
    original_record := produce_original_record_with_ownership(ownerUsers, ownerGroups)
    
    allow with input as produce_input_doc_by_role_with_groups("tarcinapp.member", true, ["my-group"], payload, original_record)
}

# Test member with user's group as owner (user's group in ownerGroups, public visibility)
test_allow_to_member_as_owner_group_public if {
    user_groups = ["my-group"]
    ownerUsers = ["different-user"]
    ownerGroups = ["my-group"]
    
    payload := produce_payload_with_ownership(ownerUsers, ownerGroups)
    original_record := produce_original_record_with_ownership(ownerUsers, ownerGroups)
    
    allow with input as produce_input_doc_by_role_with_groups("tarcinapp.member", true, user_groups, payload, original_record)
}

# Test member with user's group as owner (user's group in ownerGroups, protected visibility)
test_allow_to_member_as_owner_group_protected if {
    user_groups = ["my-group"]
    ownerUsers = ["different-user"]
    ownerGroups = ["my-group"]
    
    payload := produce_payload_with_ownership(ownerUsers, ownerGroups)
    original_record := produce_original_record_with_ownership(ownerUsers, ownerGroups)
    protected_original_record := object.union(original_record, {"_visibility": "protected"})
    
    allow with input as produce_input_doc_by_role_with_groups("tarcinapp.member", true, user_groups, payload, protected_original_record)
}

# Test member NOT allowed with user's group as owner but private visibility
test_not_allow_to_member_as_owner_group_private if {
    user_groups = ["my-group"]
    ownerUsers = ["different-user"]
    ownerGroups = ["my-group"]
    
    payload := produce_payload_with_ownership(ownerUsers, ownerGroups)
    original_record := produce_original_record_with_ownership(ownerUsers, ownerGroups)
    private_original_record := object.union(original_record, {"_visibility": "private"})
    
    not allow with input as produce_input_doc_by_role_with_groups("tarcinapp.member", true, user_groups, payload, private_original_record)
}

# Test member NOT allowed when not owner (different user and group)
test_not_allow_to_member_not_owner if {
    user_groups = ["my-group"]
    ownerUsers = ["different-user"]
    ownerGroups = ["different-group"]
    
    payload := produce_payload_with_ownership(ownerUsers, ownerGroups)
    original_record := produce_original_record_with_ownership(ownerUsers, ownerGroups)
    
    not allow with input as produce_input_doc_by_role_with_groups("tarcinapp.member", true, user_groups, payload, original_record)
}

# Test member with ownerUsers in payload containing user ID
test_allow_to_member_with_ownerUsers_in_payload if {
    user_id = "ebe92b0c-bda2-49d0-99d0-feb538aa7db6"
    user_groups = ["my-group"]
    ownerUsers = [user_id]
    ownerGroups = ["other-group"]
    
    payload := produce_payload_with_ownership(ownerUsers, ownerGroups)
    original_record := produce_original_record_with_ownership(ownerUsers, ownerGroups)
    
    allow with input as produce_input_doc_by_role_with_groups("tarcinapp.member", true, user_groups, payload, original_record)
}

# Test member NOT allowed with ownerUsers in payload not containing user ID
test_not_allow_to_member_with_ownerUsers_not_containing_user if {
    user_groups = ["my-group"]
    ownerUsers = ["different-user"]
    ownerGroups = ["other-group"]
    
    payload := produce_payload_with_ownership(ownerUsers, ownerGroups)
    original_record := produce_original_record_with_ownership(ownerUsers, ownerGroups)
    
    not allow with input as produce_input_doc_by_role_with_groups("tarcinapp.member", true, user_groups, payload, original_record)
}

# Test member with ownerGroups in payload containing user's groups
test_allow_to_member_with_ownerGroups_in_payload if {
    user_groups = ["my-group", "another-group"]
    ownerUsers = ["different-user"]
    ownerGroups = ["my-group"]
    
    payload := produce_payload_with_ownership(ownerUsers, ownerGroups)
    original_record := produce_original_record_with_ownership(ownerUsers, ownerGroups)
    
    allow with input as produce_input_doc_by_role_with_groups("tarcinapp.member", true, user_groups, payload, original_record)
}

# Test member NOT allowed with ownerGroups in payload not containing user's groups
test_not_allow_to_member_with_ownerGroups_not_containing_user_groups if {
    user_groups = ["my-group"]
    ownerUsers = ["different-user"]
    ownerGroups = ["different-group"]
    
    payload := produce_payload_with_ownership(ownerUsers, ownerGroups)
    original_record := produce_original_record_with_ownership(ownerUsers, ownerGroups)
    
    not allow with input as produce_input_doc_by_role_with_groups("tarcinapp.member", true, user_groups, payload, original_record)
}

# ============================================================================
# ADMIN TESTS - ROLE SCOPE VALIDATION
# ============================================================================

# Test that admin roles from different scopes don't work
test_not_allow_to_lists_admin if {
    not allow with input as produce_input_doc_by_role("tarcinapp.lists.admin", true)
}

test_not_allow_to_reactions_admin if {
    not allow with input as produce_input_doc_by_role("tarcinapp.reactions.admin", true)
}

test_not_allow_to_lists_update_admin if {
    not allow with input as produce_input_doc_by_role("tarcinapp.lists.update.admin", true)
}

test_not_allow_to_reactions_update_admin if {
    not allow with input as produce_input_doc_by_role("tarcinapp.reactions.update.admin", true)
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