package policies.auth.routes.lists.updateAllLists.policy

import data.policies.util.common.test as test

# Refactored to accept a full requestPayload
produce_input_doc_by_role(role, is_email_verified) = test_body if {
    test_body := produce_input_doc_by_role_with_payload(role, is_email_verified, base_payload)
}

produce_input_doc_by_role_with_payload(role, is_email_verified, requestPayload) = test_body if {
    test_body = {
        "appShortcode": "tarcinapp",
        "httpMethod": "PUT",
        "requestPath": "/lists",
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
        "requestPayload": requestPayload
    }
}

# Helper for default payload
base_payload = {
    "_id": "123",
    "_name": "test list",
    "_visibility": "public",
    "_ownerUsers": ["any-owner"],
    "_ownerGroups": ["any-owner-group"],
    "_validFromDateTime": "2020-01-01T00:00:00Z",
    "_validUntilDateTime": null
}

# Update all test cases to use the new function signature

test_allow_to_admin if {
    allow with input as produce_input_doc_by_role("tarcinapp.admin", true)
}

test_allow_to_records_admin if {
    allow with input as produce_input_doc_by_role("tarcinapp.records.admin", true)
}

test_allow_to_lists_admin if {
    allow with input as produce_input_doc_by_role("tarcinapp.lists.admin", true)
}

test_not_allow_to_admin_without_email_verification if {
    not allow with input as produce_input_doc_by_role("tarcinapp.admin", false)
}

test_allow_to_editor if {
    allow with input as produce_input_doc_by_role("tarcinapp.editor", true)
}

test_allow_to_records_editor if {
    allow with input as produce_input_doc_by_role("tarcinapp.records.editor", true)
}

test_allow_to_lists_editor if {
    allow with input as produce_input_doc_by_role("tarcinapp.lists.editor", true)
}

test_not_allow_to_editor_without_email_verification if {
    not allow with input as produce_input_doc_by_role("tarcinapp.editor", false)
}

test_not_allow_to_member if {
    not allow with input as produce_input_doc_by_role("tarcinapp.member", true)
}

test_not_allow_to_member_email_verification if {
    not allow with input as produce_input_doc_by_role("tarcinapp.member", false)
}

test_not_allow_to_visitor if {
    not allow with input as produce_input_doc_by_role("tarcinapp.visitor", true)
}

test_not_allow_to_non_admin_editor_roles_member if {
    not allow with input as produce_input_doc_by_role("tarcinapp.member", true)
}

test_not_allow_to_non_admin_editor_roles_visitor if {
    not allow with input as produce_input_doc_by_role("tarcinapp.visitor", true)
}

test_not_allow_to_non_admin_editor_roles_records_member if {
    not allow with input as produce_input_doc_by_role("tarcinapp.records.member", true)
}

test_not_allow_to_non_admin_editor_roles_lists_member if {
    not allow with input as produce_input_doc_by_role("tarcinapp.lists.member", true)
}

test_not_allow_to_non_admin_editor_roles_records_visitor if {
    not allow with input as produce_input_doc_by_role("tarcinapp.records.visitor", true)
}

test_not_allow_to_non_admin_editor_roles_lists_visitor if {
    not allow with input as produce_input_doc_by_role("tarcinapp.lists.visitor", true)
}

# Forbidden field test

test_not_allow_to_editor_with_forbidden_field if {
    forbidden_payload := object.union(base_payload, {"_createdDateTime": "2020-01-01T00:00:00Z"})
    not allow with input as produce_input_doc_by_role_with_payload("tarcinapp.editor", true, forbidden_payload)
}

# ============================================================================
# OPERATION-LEVEL EDITOR ROLES
# ============================================================================

test_allow_to_lists_update_editor if {
    allow with input as produce_input_doc_by_role("tarcinapp.lists.update.editor", true)
}

test_allow_to_records_update_editor if {
    allow with input as produce_input_doc_by_role("tarcinapp.records.update.editor", true)
}

test_not_allow_to_lists_update_editor_without_email_verification if {
    not allow with input as produce_input_doc_by_role("tarcinapp.lists.update.editor", false)
}

test_not_allow_to_records_update_editor_without_email_verification if {
    not allow with input as produce_input_doc_by_role("tarcinapp.records.update.editor", false)
}

# ============================================================================
# OPERATION-LEVEL ADMIN ROLES
# ============================================================================

test_allow_to_lists_update_admin if {
    allow with input as produce_input_doc_by_role("tarcinapp.lists.update.admin", true)
}

test_allow_to_records_update_admin if {
    allow with input as produce_input_doc_by_role("tarcinapp.records.update.admin", true)
}

test_not_allow_to_lists_update_admin_without_email_verification if {
    not allow with input as produce_input_doc_by_role("tarcinapp.lists.update.admin", false)
}

test_not_allow_to_records_update_admin_without_email_verification if {
    not allow with input as produce_input_doc_by_role("tarcinapp.records.update.admin", false)
}

test_allow_to_lists_update_admin_with_forbidden_fields if {
    # Admin should be allowed even with forbidden fields
    forbidden_payload := object.union(base_payload, {
        "_createdDateTime": "2020-01-01T00:00:00Z",
        "_lastUpdatedDateTime": "2020-01-01T00:00:00Z"
    })
    allow with input as produce_input_doc_by_role_with_payload("tarcinapp.lists.update.admin", true, forbidden_payload)
}

test_allow_to_records_update_admin_with_forbidden_fields if {
    # Admin should be allowed even with forbidden fields
    forbidden_payload := object.union(base_payload, {
        "_createdDateTime": "2020-01-01T00:00:00Z",
        "_lastUpdatedDateTime": "2020-01-01T00:00:00Z"
    })
    allow with input as produce_input_doc_by_role_with_payload("tarcinapp.records.update.admin", true, forbidden_payload)
}

# ============================================================================
# FIELD-LEVEL PERMISSIONS (should override forbidden field restrictions)
# ============================================================================

test_allow_to_editor_with_field_level_permission_for_createdDateTime if {
    # User has field-level permission to update _createdDateTime
    custom_payload := object.union(base_payload, {"_createdDateTime": "2020-01-01T00:00:00Z"})
    custom_roles := [
        "offline_access",
        "uma_authorization",
        "tarcinapp.editor",
        "tarcinapp.lists.fields._createdDateTime.update"
    ]
    
    allow with input as {
        "appShortcode": "tarcinapp",
        "httpMethod": "PUT",
        "requestPath": "/lists",
        "queryParams": {},
        "encodedJwt": test.produce_token({
            "sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
            "name": "John Doe",
            "admin": true,
            "iat": 1516239022,
            "email_verified": true,
            "groups": ["my-group"],
            "roles": custom_roles,
        }),
        "requestPayload": custom_payload
    }
}

test_allow_to_editor_with_field_level_manage_permission_for_createdDateTime if {
    # User has field-level manage permission (grants all operations)
    custom_payload := object.union(base_payload, {"_createdDateTime": "2020-01-01T00:00:00Z"})
    custom_roles := [
        "offline_access",
        "uma_authorization",
        "tarcinapp.editor",
        "tarcinapp.lists.fields._createdDateTime.manage"
    ]
    
    allow with input as {
        "appShortcode": "tarcinapp",
        "httpMethod": "PUT",
        "requestPath": "/lists",
        "queryParams": {},
        "encodedJwt": test.produce_token({
            "sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
            "name": "John Doe",
            "admin": true,
            "iat": 1516239022,
            "email_verified": true,
            "groups": ["my-group"],
            "roles": custom_roles,
        }),
        "requestPayload": custom_payload
    }
}

test_allow_to_editor_with_field_level_permission_for_lastUpdatedDateTime if {
    # User has field-level permission to update _lastUpdatedDateTime
    custom_payload := object.union(base_payload, {"_lastUpdatedDateTime": "2020-01-01T00:00:00Z"})
    custom_roles := [
        "offline_access",
        "uma_authorization",
        "tarcinapp.editor",
        "tarcinapp.lists.fields._lastUpdatedDateTime.update"
    ]
    
    allow with input as {
        "appShortcode": "tarcinapp",
        "httpMethod": "PUT",
        "requestPath": "/lists",
        "queryParams": {},
        "encodedJwt": test.produce_token({
            "sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
            "name": "John Doe",
            "admin": true,
            "iat": 1516239022,
            "email_verified": true,
            "groups": ["my-group"],
            "roles": custom_roles,
        }),
        "requestPayload": custom_payload
    }
}

# ============================================================================
# MIXED ROLE SCENARIOS
# ============================================================================

test_allow_to_editor_with_multiple_field_permissions if {
    # User has multiple field-level permissions
    custom_payload := object.union(base_payload, {
        "_createdDateTime": "2020-01-01T00:00:00Z",
        "_lastUpdatedDateTime": "2020-01-01T00:00:00Z"
    })
    custom_roles := [
        "offline_access",
        "uma_authorization",
        "tarcinapp.editor",
        "tarcinapp.lists.fields._createdDateTime.update",
        "tarcinapp.lists.fields._lastUpdatedDateTime.update"
    ]
    
    allow with input as {
        "appShortcode": "tarcinapp",
        "httpMethod": "PUT",
        "requestPath": "/lists",
        "queryParams": {},
        "encodedJwt": test.produce_token({
            "sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
            "name": "John Doe",
            "admin": true,
            "iat": 1516239022,
            "email_verified": true,
            "groups": ["my-group"],
            "roles": custom_roles,
        }),
        "requestPayload": custom_payload
    }
}

test_not_allow_to_editor_with_partial_field_permissions if {
    # User has permission for one forbidden field but not another
    custom_payload := object.union(base_payload, {
        "_createdDateTime": "2020-01-01T00:00:00Z",
        "_lastUpdatedDateTime": "2020-01-01T00:00:00Z"
    })
    custom_roles := [
        "offline_access",
        "uma_authorization",
        "tarcinapp.editor",
        "tarcinapp.lists.fields._createdDateTime.update"
        # Missing permission for _lastUpdatedDateTime
    ]
    
    not allow with input as {
        "appShortcode": "tarcinapp",
        "httpMethod": "PUT",
        "requestPath": "/lists",
        "queryParams": {},
        "encodedJwt": test.produce_token({
            "sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
            "name": "John Doe",
            "admin": true,
            "iat": 1516239022,
            "email_verified": true,
            "groups": ["my-group"],
            "roles": custom_roles,
        }),
        "requestPayload": custom_payload
    }
}

# ============================================================================
# DIFFERENT SCOPES
# ============================================================================

test_allow_to_records_editor_with_records_scope if {
    # User has records scope editor role
    allow with input as produce_input_doc_by_role("tarcinapp.records.editor", true)
}

test_allow_to_lists_editor_with_lists_scope if {
    # User has lists scope editor role
    allow with input as produce_input_doc_by_role("tarcinapp.lists.editor", true)
}

test_not_allow_to_entities_editor_with_entities_scope if {
    # User has entities scope editor role but trying to update lists
    not allow with input as produce_input_doc_by_role("tarcinapp.entities.editor", true)
}

test_not_allow_to_reactions_editor_with_reactions_scope if {
    # User has reactions scope editor role but trying to update lists
    not allow with input as produce_input_doc_by_role("tarcinapp.reactions.editor", true)
}

# ============================================================================
# ADMIN WITH FIELD-LEVEL PERMISSIONS
# ============================================================================

test_allow_to_admin_with_field_level_permissions if {
    # Admin should be allowed even with field-level permissions
    custom_payload := object.union(base_payload, {
        "_createdDateTime": "2020-01-01T00:00:00Z",
        "_lastUpdatedDateTime": "2020-01-01T00:00:00Z"
    })
    custom_roles := [
        "offline_access",
        "uma_authorization",
        "tarcinapp.admin",
        "tarcinapp.lists.fields._createdDateTime.update",
        "tarcinapp.lists.fields._lastUpdatedDateTime.update"
    ]
    
    allow with input as {
        "appShortcode": "tarcinapp",
        "httpMethod": "PUT",
        "requestPath": "/lists",
        "queryParams": {},
        "encodedJwt": test.produce_token({
            "sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
            "name": "John Doe",
            "admin": true,
            "iat": 1516239022,
            "email_verified": true,
            "groups": ["my-group"],
            "roles": custom_roles,
        }),
        "requestPayload": custom_payload
    }
}

# ============================================================================
# EDGE CASES
# ============================================================================

test_not_allow_to_editor_with_find_only_field_permission if {
    # User has find permission but not update permission for forbidden field
    custom_payload := object.union(base_payload, {"_createdDateTime": "2020-01-01T00:00:00Z"})
    custom_roles := [
        "offline_access",
        "uma_authorization",
        "tarcinapp.editor",
        "tarcinapp.lists.fields._createdDateTime.find"  # Only find, not update
    ]
    
    not allow with input as {
        "appShortcode": "tarcinapp",
        "httpMethod": "PUT",
        "requestPath": "/lists",
        "queryParams": {},
        "encodedJwt": test.produce_token({
            "sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
            "name": "John Doe",
            "admin": true,
            "iat": 1516239022,
            "email_verified": true,
            "groups": ["my-group"],
            "roles": custom_roles,
        }),
        "requestPayload": custom_payload
    }
}

test_not_allow_to_editor_with_create_only_field_permission if {
    # User has create permission but not update permission for forbidden field
    custom_payload := object.union(base_payload, {"_createdDateTime": "2020-01-01T00:00:00Z"})
    custom_roles := [
        "offline_access",
        "uma_authorization",
        "tarcinapp.editor",
        "tarcinapp.lists.fields._createdDateTime.create"  # Only create, not update
    ]
    
    not allow with input as {
        "appShortcode": "tarcinapp",
        "httpMethod": "PUT",
        "requestPath": "/lists",
        "queryParams": {},
        "encodedJwt": test.produce_token({
            "sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
            "name": "John Doe",
            "admin": true,
            "iat": 1516239022,
            "email_verified": true,
            "groups": ["my-group"],
            "roles": custom_roles,
        }),
        "requestPayload": custom_payload
    }
}