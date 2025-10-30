package policies.auth.routes.lists.createList.policy

import data.policies.fields.lists.policy as forbidden_fields
import data.policies.util.common.test as test

# End-to-end tests for createList policy
# Tests all role patterns and forbidden field scenarios

# ========================================
# POSITIVE TESTS - ROLES THAT SHOULD ALLOW
# ========================================

# Global scope roles (highest level)
# Test global admin role (tarcinapp.admin)
test_allow_to_global_admin if {
	allow with input as produce_input_doc_by_role("tarcinapp.admin", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		"_ownerUsers": ["some-user"],
	})
}

# Test global editor role (tarcinapp.editor)
test_allow_to_global_editor if {
	allow with input as produce_input_doc_by_role("tarcinapp.editor", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
	})
}

# Test global member role (tarcinapp.member)
test_allow_to_global_member if {
	allow with input as produce_input_doc_by_role("tarcinapp.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
	})
}

# Records scope roles (covers both entities and lists)
# Test records scope admin role (tarcinapp.records.admin)
test_allow_to_records_admin if {
	allow with input as produce_input_doc_by_role("tarcinapp.records.admin", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		"_ownerUsers": ["some-user"],
	})
}

# Test records create operation admin role (tarcinapp.records.create.admin)
test_allow_to_records_create_admin if {
	allow with input as produce_input_doc_by_role("tarcinapp.records.create.admin", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		"_ownerUsers": ["some-user"],
	})
}

# Test records scope editor role (tarcinapp.records.editor)
test_allow_to_records_editor if {
	allow with input as produce_input_doc_by_role("tarcinapp.records.editor", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
	})
}

# Test records create operation editor role (tarcinapp.records.create.editor)
test_allow_to_records_create_editor if {
	allow with input as produce_input_doc_by_role("tarcinapp.records.create.editor", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
	})
}

# Test records scope member role (tarcinapp.records.member)
test_allow_to_records_member if {
	allow with input as produce_input_doc_by_role("tarcinapp.records.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
	})
}

# Test records create operation member role (tarcinapp.records.create.member)
test_allow_to_records_create_member if {
	allow with input as produce_input_doc_by_role("tarcinapp.records.create.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
	})
}

# Lists scope roles (specific to lists)
# Test lists scope admin role (tarcinapp.lists.admin)
test_allow_to_lists_admin if {
	allow with input as produce_input_doc_by_role("tarcinapp.lists.admin", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		"_ownerUsers": ["some-user"],
	})
}

# Test lists create operation admin role (tarcinapp.lists.create.admin)
test_allow_to_lists_create_admin if {
	allow with input as produce_input_doc_by_role("tarcinapp.lists.create.admin", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		"_ownerUsers": ["some-user"],
	})
}

# Test lists scope editor role (tarcinapp.lists.editor)
test_allow_to_lists_editor if {
	allow with input as produce_input_doc_by_role("tarcinapp.lists.editor", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
	})
}

# Test lists create operation editor role (tarcinapp.lists.create.editor)
test_allow_to_lists_create_editor if {
	allow with input as produce_input_doc_by_role("tarcinapp.lists.create.editor", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
	})
}

# Test lists scope member role (tarcinapp.lists.member)
test_allow_to_lists_member if {
	allow with input as produce_input_doc_by_role("tarcinapp.lists.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
	})
}

# Test lists create operation member role (tarcinapp.lists.create.member)
test_allow_to_lists_create_member if {
	allow with input as produce_input_doc_by_role("tarcinapp.lists.create.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
	})
}

# Group access tests for member roles
# Test group access for global member
test_allow_to_global_member_correct_group if {
	allow with input as produce_input_doc_by_role("tarcinapp.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		"_ownerGroups": ["group-1"], # User belongs to group-1
	})
}

# Test group access for records scope member
test_allow_to_records_member_correct_group if {
	allow with input as produce_input_doc_by_role("tarcinapp.records.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		"_ownerGroups": ["group-1"], # User belongs to group-1
	})
}

# Test group access for lists scope member
test_allow_to_lists_member_correct_group if {
	allow with input as produce_input_doc_by_role("tarcinapp.lists.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		"_ownerGroups": ["group-1"], # User belongs to group-1
	})
}

# Test group access for lists create operation member
test_allow_to_lists_create_member_correct_group if {
	allow with input as produce_input_doc_by_role("tarcinapp.lists.create.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		"_ownerGroups": ["group-1"], # User belongs to group-1
	})
}

# ========================================
# COMPREHENSIVE _OWNERGROUPS VALIDATION TESTS
# ========================================

# Test multiple valid groups for member roles
# Test multiple valid groups for global member
test_allow_to_global_member_multiple_valid_groups if {
	allow with input as produce_input_doc_by_role("tarcinapp.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		"_ownerGroups": ["group-1", "group-3"], # User belongs to both groups
	})
}

# Test multiple valid groups for records scope member
test_allow_to_records_member_multiple_valid_groups if {
	allow with input as produce_input_doc_by_role("tarcinapp.records.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		"_ownerGroups": ["group-1", "group-3"], # User belongs to both groups
	})
}

# Test multiple valid groups for lists scope member
test_allow_to_lists_member_multiple_valid_groups if {
	allow with input as produce_input_doc_by_role("tarcinapp.lists.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		"_ownerGroups": ["group-1", "group-3"], # User belongs to both groups
	})
}

# Test multiple valid groups for lists create operation member
test_allow_to_lists_create_member_multiple_valid_groups if {
	allow with input as produce_input_doc_by_role("tarcinapp.lists.create.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		"_ownerGroups": ["group-1", "group-3"], # User belongs to both groups
	})
}

# Test no groups provided (should be allowed)
# Test no groups for global member
test_allow_to_global_member_no_groups if {
	allow with input as produce_input_doc_by_role("tarcinapp.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		# No _ownerGroups provided - should be allowed
	})
}

# Test no groups for records scope member
test_allow_to_records_member_no_groups if {
	allow with input as produce_input_doc_by_role("tarcinapp.records.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		# No _ownerGroups provided - should be allowed
	})
}

# Test no groups for lists scope member
test_allow_to_lists_member_no_groups if {
	allow with input as produce_input_doc_by_role("tarcinapp.lists.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		# No _ownerGroups provided - should be allowed
	})
}

# Test no groups for lists create operation member
test_allow_to_lists_create_member_no_groups if {
	allow with input as produce_input_doc_by_role("tarcinapp.lists.create.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		# No _ownerGroups provided - should be allowed
	})
}

# Test empty groups array (should be allowed)
# Test empty groups for global member
test_allow_to_global_member_empty_groups if {
	allow with input as produce_input_doc_by_role("tarcinapp.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		"_ownerGroups": [], # Empty array - should be allowed
	})
}

# Test empty groups for records scope member
test_allow_to_records_member_empty_groups if {
	allow with input as produce_input_doc_by_role("tarcinapp.records.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		"_ownerGroups": [], # Empty array - should be allowed
	})
}

# Test empty groups for lists scope member
test_allow_to_lists_member_empty_groups if {
	allow with input as produce_input_doc_by_role("tarcinapp.lists.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		"_ownerGroups": [], # Empty array - should be allowed
	})
}

# Test empty groups for lists create operation member
test_allow_to_lists_create_member_empty_groups if {
	allow with input as produce_input_doc_by_role("tarcinapp.lists.create.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		"_ownerGroups": [], # Empty array - should be allowed
	})
}

# ========================================
# NEGATIVE TESTS - ROLES THAT SHOULD NOT ALLOW
# ========================================

# Forbidden field tests for editor roles
# Test forbidden field for global editor
test_not_allow_to_global_editor_by_forbidden_field if {
	not allow with input as produce_input_doc_by_role("tarcinapp.editor", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		"_createdBy": "some-user", # This should be forbidden for editors
	})
}

# Test forbidden field for records scope editor
test_not_allow_to_records_editor_by_forbidden_field if {
	not allow with input as produce_input_doc_by_role("tarcinapp.records.editor", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		"_createdBy": "some-user", # This should be forbidden for editors
	})
}

# Test forbidden field for lists scope editor
test_not_allow_to_lists_editor_by_forbidden_field if {
	not allow with input as produce_input_doc_by_role("tarcinapp.lists.editor", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		"_createdBy": "some-user", # This should be forbidden for editors
	})
}

# Test forbidden field for lists create operation editor
test_not_allow_to_lists_create_editor_by_forbidden_field if {
	not allow with input as produce_input_doc_by_role("tarcinapp.lists.create.editor", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		"_createdBy": "some-user", # This should be forbidden for editors
	})
}

# Forbidden field tests for member roles
# Test forbidden field for global member
test_not_allow_to_global_member_by_forbidden_field if {
	not allow with input as produce_input_doc_by_role("tarcinapp.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		"_createdBy": "some-user", # This should be forbidden for members
	})
}

# Test forbidden field for records scope member
test_not_allow_to_records_member_by_forbidden_field if {
	not allow with input as produce_input_doc_by_role("tarcinapp.records.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		"_createdBy": "some-user", # This should be forbidden for members
	})
}

# Test forbidden field for lists scope member
test_not_allow_to_lists_member_by_forbidden_field if {
	not allow with input as produce_input_doc_by_role("tarcinapp.lists.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		"_createdBy": "some-user", # This should be forbidden for members
	})
}

# Test forbidden field for lists create operation member
test_not_allow_to_lists_create_member_by_forbidden_field if {
	not allow with input as produce_input_doc_by_role("tarcinapp.lists.create.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		"_createdBy": "some-user", # This should be forbidden for members
	})
}

# Email verification tests for member roles
# Test email verification for global member
test_not_allow_to_global_member_email_verification if {
	not allow with input as produce_input_doc_by_role("tarcinapp.member", false, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
	})
}

# Test email verification for records scope member
test_not_allow_to_records_member_email_verification if {
	not allow with input as produce_input_doc_by_role("tarcinapp.records.member", false, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
	})
}

# Test email verification for lists scope member
test_not_allow_to_lists_member_email_verification if {
	not allow with input as produce_input_doc_by_role("tarcinapp.lists.member", false, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
	})
}

# Test email verification for lists create operation member
test_not_allow_to_lists_create_member_email_verification if {
	not allow with input as produce_input_doc_by_role("tarcinapp.lists.create.member", false, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
	})
}

# Invalid group tests for member roles
# Test invalid group for global member
test_not_allow_to_global_member_by_invalid_group if {
	not allow with input as produce_input_doc_by_role("tarcinapp.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		"_ownerGroups": ["group-2"], # User doesn't belong to group-2
	})
}

# Test invalid group for records scope member
test_not_allow_to_records_member_by_invalid_group if {
	not allow with input as produce_input_doc_by_role("tarcinapp.records.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		"_ownerGroups": ["group-2"], # User doesn't belong to group-2
	})
}

# Test invalid group for lists scope member
test_not_allow_to_lists_member_by_invalid_group if {
	not allow with input as produce_input_doc_by_role("tarcinapp.lists.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		"_ownerGroups": ["group-2"], # User doesn't belong to group-2
	})
}

# Test invalid group for lists create operation member
test_not_allow_to_lists_create_member_by_invalid_group if {
	not allow with input as produce_input_doc_by_role("tarcinapp.lists.create.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		"_ownerGroups": ["group-2"], # User doesn't belong to group-2
	})
}

# Comprehensive _ownerGroups validation negative tests
# Test mixed valid and invalid groups for member roles
# Test mixed groups for global member
test_not_allow_to_global_member_by_mixed_groups if {
	not allow with input as produce_input_doc_by_role("tarcinapp.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		"_ownerGroups": ["group-1", "group-2"], # group-1 is valid, group-2 is invalid
	})
}

# Test mixed groups for records scope member
test_not_allow_to_records_member_by_mixed_groups if {
	not allow with input as produce_input_doc_by_role("tarcinapp.records.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		"_ownerGroups": ["group-1", "group-2"], # group-1 is valid, group-2 is invalid
	})
}

# Test mixed groups for lists scope member
test_not_allow_to_lists_member_by_mixed_groups if {
	not allow with input as produce_input_doc_by_role("tarcinapp.lists.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		"_ownerGroups": ["group-1", "group-2"], # group-1 is valid, group-2 is invalid
	})
}

# Test mixed groups for lists create operation member
test_not_allow_to_lists_create_member_by_mixed_groups if {
	not allow with input as produce_input_doc_by_role("tarcinapp.lists.create.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		"_ownerGroups": ["group-1", "group-2"], # group-1 is valid, group-2 is invalid
	})
}

# Test multiple invalid groups for member roles
# Test multiple invalid groups for global member
test_not_allow_to_global_member_by_multiple_invalid_groups if {
	not allow with input as produce_input_doc_by_role("tarcinapp.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		"_ownerGroups": ["group-2", "group-4"], # User doesn't belong to either group
	})
}

# Test multiple invalid groups for records scope member
test_not_allow_to_records_member_by_multiple_invalid_groups if {
	not allow with input as produce_input_doc_by_role("tarcinapp.records.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		"_ownerGroups": ["group-2", "group-4"], # User doesn't belong to either group
	})
}

# Test multiple invalid groups for lists scope member
test_not_allow_to_lists_member_by_multiple_invalid_groups if {
	not allow with input as produce_input_doc_by_role("tarcinapp.lists.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		"_ownerGroups": ["group-2", "group-4"], # User doesn't belong to either group
	})
}

# Test multiple invalid groups for lists create operation member
test_not_allow_to_lists_create_member_by_multiple_invalid_groups if {
	not allow with input as produce_input_doc_by_role("tarcinapp.lists.create.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
		"_ownerGroups": ["group-2", "group-4"], # User doesn't belong to either group
	})
}

# ========================================
# FIELD-LEVEL ROLE TESTS
# ========================================

# Test field-level roles for member roles - should allow forbidden fields when user has field-level permissions
# Test _createdBy field access for global member with field-level create permission
test_allow_to_global_member_with_createdBy_field_permission if {
	allow with input as produce_input_doc_by_role_with_field_permission(
		"tarcinapp.member", true, {
			"_name": "Test List",
			"description": "Test Description",
			"_visibility": "public",
			"_createdBy": "some-user", # This should be allowed due to field-level permission
		},
		"tarcinapp.lists.fields._createdBy.create",
	)
}

# Test _createdBy field access for records scope member with field-level create permission
test_allow_to_records_member_with_createdBy_field_permission if {
	allow with input as produce_input_doc_by_role_with_field_permission(
		"tarcinapp.records.member", true, {
			"_name": "Test List",
			"description": "Test Description",
			"_visibility": "public",
			"_createdBy": "some-user", # This should be allowed due to field-level permission
		},
		"tarcinapp.lists.fields._createdBy.create",
	)
}

# Test _createdBy field access for lists scope member with field-level create permission
test_allow_to_lists_member_with_createdBy_field_permission if {
	allow with input as produce_input_doc_by_role_with_field_permission(
		"tarcinapp.lists.member", true, {
			"_name": "Test List",
			"description": "Test Description",
			"_visibility": "public",
			"_createdBy": "some-user", # This should be allowed due to field-level permission
		},
		"tarcinapp.lists.fields._createdBy.create",
	)
}

# Test _createdBy field access for lists create operation member with field-level create permission
test_allow_to_lists_create_member_with_createdBy_field_permission if {
	allow with input as produce_input_doc_by_role_with_field_permission(
		"tarcinapp.lists.create.member", true, {
			"_name": "Test List",
			"description": "Test Description",
			"_visibility": "public",
			"_createdBy": "some-user", # This should be allowed due to field-level permission
		},
		"tarcinapp.lists.fields._createdBy.create",
	)
}

# Test _createdDateTime field access for member roles with field-level create permission
# Test _createdDateTime field access for global member with field-level create permission
test_allow_to_global_member_with_createdDateTime_field_permission if {
	allow with input as produce_input_doc_by_role_with_field_permission(
		"tarcinapp.member", true, {
			"_name": "Test List",
			"description": "Test Description",
			"_visibility": "public",
			"_createdDateTime": "2023-01-01T00:00:00Z", # This should be allowed due to field-level permission
		},
		"tarcinapp.lists.fields._createdDateTime.create",
	)
}

# Test _createdDateTime field access for records scope member with field-level create permission
test_allow_to_records_member_with_createdDateTime_field_permission if {
	allow with input as produce_input_doc_by_role_with_field_permission(
		"tarcinapp.records.member", true, {
			"_name": "Test List",
			"description": "Test Description",
			"_visibility": "public",
			"_createdDateTime": "2023-01-01T00:00:00Z", # This should be allowed due to field-level permission
		},
		"tarcinapp.lists.fields._createdDateTime.create",
	)
}

# Test _createdDateTime field access for lists scope member with field-level create permission
test_allow_to_lists_member_with_createdDateTime_field_permission if {
	allow with input as produce_input_doc_by_role_with_field_permission(
		"tarcinapp.lists.member", true, {
			"_name": "Test List",
			"description": "Test Description",
			"_visibility": "public",
			"_createdDateTime": "2023-01-01T00:00:00Z", # This should be allowed due to field-level permission
		},
		"tarcinapp.lists.fields._createdDateTime.create",
	)
}

# Test _createdDateTime field access for lists create operation member with field-level create permission
test_allow_to_lists_create_member_with_createdDateTime_field_permission if {
	allow with input as produce_input_doc_by_role_with_field_permission(
		"tarcinapp.lists.create.member", true, {
			"_name": "Test List",
			"description": "Test Description",
			"_visibility": "public",
			"_createdDateTime": "2023-01-01T00:00:00Z", # This should be allowed due to field-level permission
		},
		"tarcinapp.lists.fields._createdDateTime.create",
	)
}

# Test _ownerUsers field access for member roles with field-level create permission
# Test _ownerUsers field access for global member with field-level create permission
test_allow_to_global_member_with_ownerUsers_field_permission if {
	allow with input as produce_input_doc_by_role_with_field_permission(
		"tarcinapp.member", true, {
			"_name": "Test List",
			"description": "Test Description",
			"_visibility": "public",
			"_ownerUsers": ["user-1", "user-2"], # This should be allowed due to field-level permission
		},
		"tarcinapp.lists.fields._ownerUsers.create",
	)
}

# Test _ownerUsers field access for records scope member with field-level create permission
test_allow_to_records_member_with_ownerUsers_field_permission if {
	allow with input as produce_input_doc_by_role_with_field_permission(
		"tarcinapp.records.member", true, {
			"_name": "Test List",
			"description": "Test Description",
			"_visibility": "public",
			"_ownerUsers": ["user-1", "user-2"], # This should be allowed due to field-level permission
		},
		"tarcinapp.lists.fields._ownerUsers.create",
	)
}

# Test _ownerUsers field access for lists scope member with field-level create permission
test_allow_to_lists_member_with_ownerUsers_field_permission if {
	allow with input as produce_input_doc_by_role_with_field_permission(
		"tarcinapp.lists.member", true, {
			"_name": "Test List",
			"description": "Test Description",
			"_visibility": "public",
			"_ownerUsers": ["user-1", "user-2"], # This should be allowed due to field-level permission
		},
		"tarcinapp.lists.fields._ownerUsers.create",
	)
}

# Test _ownerUsers field access for lists create operation member with field-level create permission
test_allow_to_lists_create_member_with_ownerUsers_field_permission if {
	allow with input as produce_input_doc_by_role_with_field_permission(
		"tarcinapp.lists.create.member", true, {
			"_name": "Test List",
			"description": "Test Description",
			"_visibility": "public",
			"_ownerUsers": ["user-1", "user-2"], # This should be allowed due to field-level permission
		},
		"tarcinapp.lists.fields._ownerUsers.create",
	)
}

# Test field-level manage permission (should grant all field permissions)
# Test _createdBy field access for global member with field-level manage permission
test_allow_to_global_member_with_createdBy_manage_permission if {
	allow with input as produce_input_doc_by_role_with_field_permission(
		"tarcinapp.member", true, {
			"_name": "Test List",
			"description": "Test Description",
			"_visibility": "public",
			"_createdBy": "some-user", # This should be allowed due to field-level manage permission
		},
		"tarcinapp.lists.fields._createdBy.manage",
	)
}

# Test _createdBy field access for lists scope member with field-level manage permission
test_allow_to_lists_member_with_createdBy_manage_permission if {
	allow with input as produce_input_doc_by_role_with_field_permission(
		"tarcinapp.lists.member", true, {
			"_name": "Test List",
			"description": "Test Description",
			"_visibility": "public",
			"_createdBy": "some-user", # This should be allowed due to field-level manage permission
		},
		"tarcinapp.lists.fields._createdBy.manage",
	)
}

# Test field-level roles for editor roles - should allow forbidden fields when user has field-level permissions
# Test _createdBy field access for global editor with field-level create permission
test_allow_to_global_editor_with_createdBy_field_permission if {
	allow with input as produce_input_doc_by_role_with_field_permission(
		"tarcinapp.editor", true, {
			"_name": "Test List",
			"description": "Test Description",
			"_visibility": "public",
			"_createdBy": "some-user", # This should be allowed due to field-level permission
		},
		"tarcinapp.lists.fields._createdBy.create",
	)
}

# Test _createdBy field access for records scope editor with field-level create permission
test_allow_to_records_editor_with_createdBy_field_permission if {
	allow with input as produce_input_doc_by_role_with_field_permission(
		"tarcinapp.records.editor", true, {
			"_name": "Test List",
			"description": "Test Description",
			"_visibility": "public",
			"_createdBy": "some-user", # This should be allowed due to field-level permission
		},
		"tarcinapp.lists.fields._createdBy.create",
	)
}

# Test _createdBy field access for lists scope editor with field-level create permission
test_allow_to_lists_editor_with_createdBy_field_permission if {
	allow with input as produce_input_doc_by_role_with_field_permission(
		"tarcinapp.lists.editor", true, {
			"_name": "Test List",
			"description": "Test Description",
			"_visibility": "public",
			"_createdBy": "some-user", # This should be allowed due to field-level permission
		},
		"tarcinapp.lists.fields._createdBy.create",
	)
}

# Test _createdBy field access for lists create operation editor with field-level create permission
test_allow_to_lists_create_editor_with_createdBy_field_permission if {
	allow with input as produce_input_doc_by_role_with_field_permission(
		"tarcinapp.lists.create.editor", true, {
			"_name": "Test List",
			"description": "Test Description",
			"_visibility": "public",
			"_createdBy": "some-user", # This should be allowed due to field-level permission
		},
		"tarcinapp.lists.fields._createdBy.create",
	)
}

# Test field-level roles for visitor roles - should NOT allow creation even with field-level permissions
# Test _createdBy field access for global visitor with field-level create permission (should still deny)
test_not_allow_to_global_visitor_with_createdBy_field_permission if {
	not allow with input as produce_input_doc_by_role_with_field_permission(
		"tarcinapp.visitor", true, {
			"_name": "Test List",
			"description": "Test Description",
			"_visibility": "public",
			"_createdBy": "some-user", # Should still be denied - visitors cannot create
		},
		"tarcinapp.lists.fields._createdBy.create",
	)
}

# Test _createdBy field access for records scope visitor with field-level create permission (should still deny)
test_not_allow_to_records_visitor_with_createdBy_field_permission if {
	not allow with input as produce_input_doc_by_role_with_field_permission(
		"tarcinapp.records.visitor", true, {
			"_name": "Test List",
			"description": "Test Description",
			"_visibility": "public",
			"_createdBy": "some-user", # Should still be denied - visitors cannot create
		},
		"tarcinapp.lists.fields._createdBy.create",
	)
}

# Test _createdBy field access for lists scope visitor with field-level create permission (should still deny)
test_not_allow_to_lists_visitor_with_createdBy_field_permission if {
	not allow with input as produce_input_doc_by_role_with_field_permission(
		"tarcinapp.lists.visitor", true, {
			"_name": "Test List",
			"description": "Test Description",
			"_visibility": "public",
			"_createdBy": "some-user", # Should still be denied - visitors cannot create
		},
		"tarcinapp.lists.fields._createdBy.create",
	)
}

# Test _createdBy field access for lists create operation visitor with field-level create permission (should still deny)
test_not_allow_to_lists_create_visitor_with_createdBy_field_permission if {
	not allow with input as produce_input_doc_by_role_with_field_permission(
		"tarcinapp.lists.create.visitor", true, {
			"_name": "Test List",
			"description": "Test Description",
			"_visibility": "public",
			"_createdBy": "some-user", # Should still be denied - visitors cannot create
		},
		"tarcinapp.lists.fields._createdBy.create",
	)
}

# Test field-level roles with wrong scope - should NOT allow access
# Test _createdBy field access for global member with entities scope field permission (should deny)
test_not_allow_to_global_member_with_entities_scope_field_permission if {
	not allow with input as produce_input_doc_by_role_with_field_permission(
		"tarcinapp.member", true, {
			"_name": "Test List",
			"description": "Test Description",
			"_visibility": "public",
			"_createdBy": "some-user", # Should be denied - wrong scope (entities vs lists)
		},
		"tarcinapp.entities.fields._createdBy.create",
	)
}

# Test _createdBy field access for lists member with entities scope field permission (should deny)
test_not_allow_to_lists_member_with_entities_scope_field_permission if {
	not allow with input as produce_input_doc_by_role_with_field_permission(
		"tarcinapp.lists.member", true, {
			"_name": "Test List",
			"description": "Test Description",
			"_visibility": "public",
			"_createdBy": "some-user", # Should be denied - wrong scope (entities vs lists)
		},
		"tarcinapp.entities.fields._createdBy.create",
	)
}

# Test field-level roles with wrong operation - should NOT allow access
# Test _createdBy field access for global member with find-only field permission (should deny)
test_not_allow_to_global_member_with_find_only_field_permission if {
	not allow with input as produce_input_doc_by_role_with_field_permission(
		"tarcinapp.member", true, {
			"_name": "Test List",
			"description": "Test Description",
			"_visibility": "public",
			"_createdBy": "some-user", # Should be denied - find permission doesn't allow create
		},
		"tarcinapp.lists.fields._createdBy.find",
	)
}

# Test _createdBy field access for lists member with update-only field permission (should deny)
test_not_allow_to_lists_member_with_update_only_field_permission if {
	not allow with input as produce_input_doc_by_role_with_field_permission(
		"tarcinapp.lists.member", true, {
			"_name": "Test List",
			"description": "Test Description",
			"_visibility": "public",
			"_createdBy": "some-user", # Should be denied - update permission doesn't allow create
		},
		"tarcinapp.lists.fields._createdBy.update",
	)
}

# Visitor role tests (should not allow creation)
# Test global visitor role (tarcinapp.visitor)
test_not_allow_to_global_visitor if {
	not allow with input as produce_input_doc_by_role("tarcinapp.visitor", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
	})
}

# Test records scope visitor role (tarcinapp.records.visitor)
test_not_allow_to_records_visitor if {
	not allow with input as produce_input_doc_by_role("tarcinapp.records.visitor", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
	})
}

# Test lists scope visitor role (tarcinapp.lists.visitor)
test_not_allow_to_lists_visitor if {
	not allow with input as produce_input_doc_by_role("tarcinapp.lists.visitor", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
	})
}

# Test lists create operation visitor role (tarcinapp.lists.create.visitor)
test_not_allow_to_lists_create_visitor if {
	not allow with input as produce_input_doc_by_role("tarcinapp.lists.create.visitor", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
	})
}

# Cross-scope role tests (should not work for lists)
# Test entities scope roles (should not work for lists)
test_not_allow_to_entities_admin if {
	not allow with input as produce_input_doc_by_role("tarcinapp.entities.admin", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
	})
}

test_not_allow_to_entities_create_admin if {
	not allow with input as produce_input_doc_by_role("tarcinapp.entities.create.admin", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
	})
}

test_not_allow_to_entities_editor if {
	not allow with input as produce_input_doc_by_role("tarcinapp.entities.editor", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
	})
}

test_not_allow_to_entities_create_editor if {
	not allow with input as produce_input_doc_by_role("tarcinapp.entities.create.editor", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
	})
}

test_not_allow_to_entities_member if {
	not allow with input as produce_input_doc_by_role("tarcinapp.entities.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
	})
}

test_not_allow_to_entities_create_member if {
	not allow with input as produce_input_doc_by_role("tarcinapp.entities.create.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
	})
}

# Cross-operation role tests (should not allow creation)
# Test lists find-only admin role (tarcinapp.lists.find.admin)
test_not_allow_to_lists_find_admin if {
	not allow with input as produce_input_doc_by_role("tarcinapp.lists.find.admin", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
	})
}

# Test lists update-only admin role (tarcinapp.lists.update.admin)
test_not_allow_to_lists_update_admin if {
	not allow with input as produce_input_doc_by_role("tarcinapp.lists.update.admin", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
	})
}

# Test lists find-only editor role (tarcinapp.lists.find.editor)
test_not_allow_to_lists_find_editor if {
	not allow with input as produce_input_doc_by_role("tarcinapp.lists.find.editor", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
	})
}

# Test lists update-only editor role (tarcinapp.lists.update.editor)
test_not_allow_to_lists_update_editor if {
	not allow with input as produce_input_doc_by_role("tarcinapp.lists.update.editor", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
	})
}

# Test lists find-only member role (tarcinapp.lists.find.member)
test_not_allow_to_lists_find_member if {
	not allow with input as produce_input_doc_by_role("tarcinapp.lists.find.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
	})
}

# Test lists update-only member role (tarcinapp.lists.update.member)
test_not_allow_to_lists_update_member if {
	not allow with input as produce_input_doc_by_role("tarcinapp.lists.update.member", true, {
		"_name": "Test List",
		"description": "Test Description",
		"_visibility": "public",
	})
}

produce_input_doc_by_role(roles, is_email_verified, requestPayload) := test_body if {
	test_body = {
		"appShortcode": "tarcinapp",
		"httpMethod": "POST",
		"requestPath": "/lists",
		"queryParams": {},
		"encodedJwt": test.produce_token({
			"sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
			"name": "John Doe",
			"admin": true,
			"iat": 1516239022,
			"email_verified": is_email_verified,
			"groups": ["group-1", "group-3"], # User belongs to group-1 and group-3
			"roles": [roles],
		}),
		"requestPayload": requestPayload,
	}
}

# Helper function to create test input with field-level permissions
produce_input_doc_by_role_with_field_permission(roles, is_email_verified, requestPayload, fieldPermission) := test_body if {
	test_body = {
		"appShortcode": "tarcinapp",
		"httpMethod": "POST",
		"requestPath": "/lists",
		"queryParams": {},
		"encodedJwt": test.produce_token({
			"sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
			"name": "John Doe",
			"admin": true,
			"iat": 1516239022,
			"email_verified": is_email_verified,
			"groups": ["group-1", "group-3"], # User belongs to group-1 and group-3
			"roles": [roles, fieldPermission], # Include both operation role and field-level permission
		}),
		"requestPayload": requestPayload,
	}
}
