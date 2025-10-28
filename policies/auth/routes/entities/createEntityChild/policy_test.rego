package policies.auth.routes.entities.createEntityChild.policy

import data.policies.util.common.test as test
import data.policies.fields.entities.policy as forbidden_fields

# ========================================
# POSITIVE TESTS - ADMIN ROLE
# ========================================

# Admin can create entity child if they can see the parent (parent is owned by user)
test_allow_admin_create_child_owned_parent if {
    allow with input as produce_input_with_parent(
        "tarcinapp.admin", 
        true, 
        {"_name": "Child Entity", "_createdBy": "some-user"}, 
        ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], 
        [], 
        "private", 
        "2020-01-01T00:00:00Z", 
        null
    )
}

# Admin can create entity child if parent is public and active
test_allow_admin_create_child_public_parent if {
    allow with input as produce_input_with_parent(
        "tarcinapp.entities.admin", 
        true, 
        {"_name": "Child Entity"}, 
        ["other-user"], 
        [], 
        "public", 
        "2020-01-01T00:00:00Z", 
        null
    )
}

# ========================================
# POSITIVE TESTS - EDITOR ROLE
# ========================================

# Editor can create entity child if they can see the parent (parent belongs to user's group)
test_allow_editor_create_child_group_parent if {
    allow with input as produce_input_with_parent(
        "tarcinapp.editor", 
        true, 
        {"_name": "Child Entity", "description": "Valid payload"}, 
        ["other-user"], 
        ["users-group-1"], 
        "protected", 
        "2020-01-01T00:00:00Z", 
        null
    )
}

# Editor can create entity child if parent is in viewerUsers and active
test_allow_editor_create_child_viewer_users_parent if {
    allow with input as produce_input_with_viewers(
        "tarcinapp.entities.editor", 
        true, 
        {"_name": "Child Entity"}, 
        ["other-user"], 
        [], 
        "private", 
        "2020-01-01T00:00:00Z", 
        null,
        ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        []
    )
}

# ========================================
# POSITIVE TESTS - MEMBER ROLE
# ========================================

# Member can create entity child if they own the parent and payload is valid
test_allow_member_create_child_owned_parent if {
    allow with input as produce_input_with_parent(
        "tarcinapp.member", 
        true, 
        {"_name": "Child Entity", "_ownerGroups": ["users-group-1"]}, 
        ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], 
        [], 
        "private", 
        "2020-01-01T00:00:00Z", 
        null
    )
}

# Member can create entity child if parent is public and active
test_allow_member_create_child_public_parent if {
    allow with input as produce_input_with_parent(
        "tarcinapp.entities.member", 
        true, 
        {"_name": "Child Entity"}, 
        ["other-user"], 
        [], 
        "public", 
        "2020-01-01T00:00:00Z", 
        null
    )
}

# ========================================
# NEGATIVE TESTS - PARENT VISIBILITY
# ========================================

# Admin can create child even if parent is private and inactive (admins can see any entity)
test_allow_admin_create_child_any_parent if {
    allow with input as produce_input_with_parent(
        "tarcinapp.admin", 
        true, 
        {"_name": "Child Entity"}, 
        ["other-user"], 
        [], 
        "private", 
        "2020-01-01T00:00:00Z", 
        "2021-01-01T00:00:00Z"
    )
}

# Editor can create child even if parent is private (editors can see any entity)
test_allow_editor_create_child_any_parent if {
    allow with input as produce_input_with_parent(
        "tarcinapp.editor", 
        true, 
        {"_name": "Child Entity"}, 
        ["other-user"], 
        [], 
        "private", 
        "2020-01-01T00:00:00Z", 
        null
    )
}

# Member cannot create child if parent is inactive
test_not_allow_member_create_child_inactive_parent if {
    not allow with input as produce_input_with_parent(
        "tarcinapp.member", 
        true, 
        {"_name": "Child Entity"}, 
        ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], 
        [], 
        "public", 
        "2020-01-01T00:00:00Z", 
        "2021-01-01T00:00:00Z"
    )
}

# ========================================
# NEGATIVE TESTS - CREATION PERMISSIONS
# ========================================

# Editor cannot create child with forbidden fields
test_not_allow_editor_with_forbidden_fields if {
    not allow with input as produce_input_with_parent(
        "tarcinapp.editor", 
        true, 
        {"_name": "Child Entity", "_createdBy": "forbidden-field"}, 
        ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], 
        [], 
        "public", 
        "2020-01-01T00:00:00Z", 
        null
    )
}

# Member cannot create child with invalid owner groups
test_not_allow_member_with_invalid_owner_groups if {
    not allow with input as produce_input_with_parent(
        "tarcinapp.member", 
        true, 
        {"_name": "Child Entity", "_ownerGroups": ["invalid-group"]}, 
        ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], 
        [], 
        "public", 
        "2020-01-01T00:00:00Z", 
        null
    )
}

# Member cannot create child without email verification
test_not_allow_member_unverified_email if {
    not allow with input as produce_input_with_parent(
        "tarcinapp.member", 
        false, 
        {"_name": "Child Entity"}, 
        ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], 
        [], 
        "public", 
        "2020-01-01T00:00:00Z", 
        null
    )
}

# ========================================
# NEGATIVE TESTS - VISITOR ROLE
# ========================================

# Visitor cannot create entity children (no visitor role support)
test_not_allow_visitor_create_child if {
    not allow with input as produce_input_with_parent(
        "tarcinapp.visitor", 
        true, 
        {"_name": "Child Entity"}, 
        ["other-user"], 
        [], 
        "public", 
        "2020-01-01T00:00:00Z", 
        null
    )
}

# ========================================
# EDGE CASE TESTS
# ========================================

# Member can create child if parent is in viewerGroups and not private
test_allow_member_create_child_viewer_groups if {
    allow with input as produce_input_with_viewers(
        "tarcinapp.member", 
        true, 
        {"_name": "Child Entity"}, 
        ["other-user"], 
        [], 
        "protected", 
        "2020-01-01T00:00:00Z", 
        null,
        [],
        ["users-group-1"]
    )
}

# Member cannot create child if parent is in viewerGroups but private
test_not_allow_member_create_child_viewer_groups_private if {
    not allow with input as produce_input_with_viewers(
        "tarcinapp.member", 
        true, 
        {"_name": "Child Entity"}, 
        ["other-user"], 
        [], 
        "private", 
        "2020-01-01T00:00:00Z", 
        null,
        [],
        ["users-group-1"]
    )
}

# ========================================
# HELPER FUNCTIONS
# ========================================

produce_input_with_parent(role, is_email_verified, requestPayload, ownerUsers, ownerGroups, visibility, validFrom, validUntil) = test_body if {
	test_body = {
		"appShortcode": "tarcinapp",
		"httpMethod": "POST",
		"requestPath": "/entities/123/children",
		"queryParams": {},
		"encodedJwt": test.produce_token({
			"sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
			"name": "John Doe",
			"admin": true,
			"iat": 1516239022,
			"email_verified": is_email_verified,
			"groups": ["users-group-1", "users-group-2"],
			"roles": [role],
		}),
		"requestPayload": requestPayload,
		"originalRecord": {
			"_id": "123",
			"name": "Parent Entity",
			"_ownerUsers": ownerUsers,
			"_ownerGroups": ownerGroups,
			"_visibility": visibility,
            "_validFromDateTime": validFrom,
            "_validUntilDateTime": validUntil
		},
	}
}

produce_input_with_viewers(role, is_email_verified, requestPayload, ownerUsers, ownerGroups, visibility, validFrom, validUntil, viewerUsers, viewerGroups) = test_body if {
	test_body = {
		"appShortcode": "tarcinapp",
		"httpMethod": "POST",
		"requestPath": "/entities/123/children",
		"queryParams": {},
		"encodedJwt": test.produce_token({
			"sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
			"name": "John Doe",
			"admin": true,
			"iat": 1516239022,
			"email_verified": is_email_verified,
			"groups": ["users-group-1", "users-group-2"],
			"roles": [role],
		}),
		"requestPayload": requestPayload,
		"originalRecord": {
			"_id": "123",
			"name": "Parent Entity",
			"_ownerUsers": ownerUsers,
			"_ownerGroups": ownerGroups,
			"_visibility": visibility,
            "_validFromDateTime": validFrom,
            "_validUntilDateTime": validUntil,
            "_viewerUsers": viewerUsers,
            "_viewerGroups": viewerGroups
		},
	}
}