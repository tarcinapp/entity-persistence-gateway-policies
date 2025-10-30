package policies.auth.routes.lists.createListChild.policy

import data.policies.fields.lists.policy as forbidden_fields
import data.policies.util.common.test as test

# ========================================
# POSITIVE TESTS - ADMIN ROLE
# ========================================

# Admin can create list child if they can see the parent (parent is owned by user)
test_allow_admin_create_child_owned_parent if {
	allow with input as produce_input_with_parent(
		"tarcinapp.admin",
		true,
		{"_name": "Child List", "_createdBy": "some-user"},
		["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
		[],
		"private",
		"2020-01-01T00:00:00Z",
		null,
	)
}

# Admin can create list child under any parent list (no restrictions)
test_allow_admin_create_child_any_parent if {
	allow with input as produce_input_with_parent(
		"tarcinapp.lists.admin",
		true,
		{"_name": "Child List"},
		["other-user"],
		[],
		"private",
		"2020-01-01T00:00:00Z",
		"2021-01-01T00:00:00Z",
	)
}

# ========================================
# POSITIVE TESTS - EDITOR ROLE
# ========================================

# Editor can create list child under any parent list
test_allow_editor_create_child_any_parent if {
	allow with input as produce_input_with_parent(
		"tarcinapp.editor",
		true,
		{"_name": "Child List", "description": "Valid payload"},
		["other-user"],
		[],
		"private",
		"2020-01-01T00:00:00Z",
		null,
	)
}

# Editor can create list child if parent is in viewerUsers and active
test_allow_editor_create_child_viewer_users_parent if {
	allow with input as produce_input_with_viewers(
		"tarcinapp.lists.editor",
		true,
		{"_name": "Child List"},
		["other-user"],
		[],
		"private",
		"2020-01-01T00:00:00Z",
		null,
		["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
		[],
	)
}

# ========================================
# POSITIVE TESTS - MEMBER ROLE
# ========================================

# Member can create list child if they own the parent and payload is valid
test_allow_member_create_child_owned_parent if {
	allow with input as produce_input_with_parent(
		"tarcinapp.member",
		true,
		{"_name": "Child List", "_ownerGroups": ["users-group-1"]},
		["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
		[],
		"private",
		"2020-01-01T00:00:00Z",
		null,
	)
}

# Member can create list child if parent is public and active
test_allow_member_create_child_public_parent if {
	allow with input as produce_input_with_parent(
		"tarcinapp.lists.member",
		true,
		{"_name": "Child List"},
		["other-user"],
		[],
		"public",
		"2020-01-01T00:00:00Z",
		null,
	)
}

# ========================================
# NEGATIVE TESTS - PARENT VISIBILITY
# ========================================

# Member cannot create child if they cannot see the parent (private, not owned)
test_not_allow_member_create_child_private_parent if {
	not allow with input as produce_input_with_parent(
		"tarcinapp.member",
		true,
		{"_name": "Child List"},
		["other-user"],
		[],
		"private",
		"2020-01-01T00:00:00Z",
		null,
	)
}

# Member cannot create child if parent is inactive
test_not_allow_member_create_child_inactive_parent if {
	not allow with input as produce_input_with_parent(
		"tarcinapp.member",
		true,
		{"_name": "Child List"},
		["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
		[],
		"public",
		"2020-01-01T00:00:00Z",
		"2021-01-01T00:00:00Z",
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
		{"_name": "Child List", "_createdBy": "forbidden-field"},
		["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
		[],
		"public",
		"2020-01-01T00:00:00Z",
		null,
	)
}

# Member cannot create child with invalid owner groups
test_not_allow_member_with_invalid_owner_groups if {
	not allow with input as produce_input_with_parent(
		"tarcinapp.member",
		true,
		{"_name": "Child List", "_ownerGroups": ["invalid-group"]},
		["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
		[],
		"public",
		"2020-01-01T00:00:00Z",
		null,
	)
}

# Member cannot create child without email verification
test_not_allow_member_unverified_email if {
	not allow with input as produce_input_with_parent(
		"tarcinapp.member",
		false,
		{"_name": "Child List"},
		["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
		[],
		"public",
		"2020-01-01T00:00:00Z",
		null,
	)
}

# ========================================
# NEGATIVE TESTS - VISITOR ROLE
# ========================================

# Visitor cannot create list children (no visitor role support)
test_not_allow_visitor_create_child if {
	not allow with input as produce_input_with_parent(
		"tarcinapp.visitor",
		true,
		{"_name": "Child List"},
		["other-user"],
		[],
		"public",
		"2020-01-01T00:00:00Z",
		null,
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
		{"_name": "Child List"},
		["other-user"],
		[],
		"protected",
		"2020-01-01T00:00:00Z",
		null,
		[],
		["users-group-1"],
	)
}

# Member cannot create child if parent is in viewerGroups but private
test_not_allow_member_create_child_viewer_groups_private if {
	not allow with input as produce_input_with_viewers(
		"tarcinapp.member",
		true,
		{"_name": "Child List"},
		["other-user"],
		[],
		"private",
		"2020-01-01T00:00:00Z",
		null,
		[],
		["users-group-1"],
	)
}

# Member can create child if parent belongs to their group (protected)
test_allow_member_create_child_group_parent if {
	allow with input as produce_input_with_parent(
		"tarcinapp.lists.member",
		true,
		{"_name": "Child List"},
		["other-user"],
		["users-group-1"],
		"protected",
		"2020-01-01T00:00:00Z",
		null,
	)
}

# ========================================
# HELPER FUNCTIONS
# ========================================

produce_input_with_parent(role, is_email_verified, requestPayload, ownerUsers, ownerGroups, visibility, validFrom, validUntil) := test_body if {
	test_body = {
		"appShortcode": "tarcinapp",
		"httpMethod": "POST",
		"requestPath": "/lists/456/children",
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
			"_id": "456",
			"name": "Parent List",
			"_ownerUsers": ownerUsers,
			"_ownerGroups": ownerGroups,
			"_visibility": visibility,
			"_validFromDateTime": validFrom,
			"_validUntilDateTime": validUntil,
		},
	}
}

produce_input_with_viewers(role, is_email_verified, requestPayload, ownerUsers, ownerGroups, visibility, validFrom, validUntil, viewerUsers, viewerGroups) := test_body if {
	test_body = {
		"appShortcode": "tarcinapp",
		"httpMethod": "POST",
		"requestPath": "/lists/456/children",
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
			"_id": "456",
			"name": "Parent List",
			"_ownerUsers": ownerUsers,
			"_ownerGroups": ownerGroups,
			"_visibility": visibility,
			"_validFromDateTime": validFrom,
			"_validUntilDateTime": validUntil,
			"_viewerUsers": viewerUsers,
			"_viewerGroups": viewerGroups,
		},
	}
}
