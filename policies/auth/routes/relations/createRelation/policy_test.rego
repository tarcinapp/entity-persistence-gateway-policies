package policies.auth.routes.relations.createRelation.policy

import data.policies.fields.relations.policy as forbidden_fields
import data.policies.util.common.test as test

# End-to-end tests for createRelation policy
# Tests all role patterns, originalRecord ownership/visibility scenarios and forbidden field cases

# ========================================
# POSITIVE TESTS - ROLES THAT SHOULD ALLOW
# ========================================

# Global scope roles (highest level)
# Test global admin role (tarcinapp.admin)
test_allow_to_global_admin if {
	allow with input as produce_input_doc_by_role(
		"tarcinapp.admin", true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
			"_validFromDateTime": "2021-01-01T00:00:00Z",
		},
		{
			"_fromMetadata": {
				"_id": "7ef64686-976f-4737-aebd-e4aea445202d",
				"_kind": "bookshelf",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_visibility": "protected",
				"_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
				"_ownerGroups": [],
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
			"_toMetadata": {
				"_id": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
				"_kind": "book",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_visibility": "public",
				"_ownerUsers": ["other-user"],
				"_ownerGroups": [],
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
		},
	)
}

# Test global editor role (tarcinapp.editor)
test_allow_to_global_editor if {
	allow with input as produce_input_doc_by_role(
		"tarcinapp.editor", true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
		},
		{
			"_fromMetadata": {
				"_id": "7ef64686-976f-4737-aebd-e4aea445202d",
				"_kind": "bookshelf",
				"_validFromDateTime": null,
				"_validUntilDateTime": null,
				"_visibility": "private",
				"_ownerUsers": ["other-user"],
				"_ownerGroups": [],
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
			"_toMetadata": {
				"_id": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
				"_kind": "book",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_visibility": "private",
				"_ownerUsers": ["other-user"],
				"_ownerGroups": [],
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
		},
	)
}

# Test global member role (tarcinapp.member) - must own the referenced list and be able to see the entity
test_allow_to_global_member if {
	allow with input as produce_input_doc_by_role(
		"tarcinapp.member", true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
		},
		{
			"_fromMetadata": {
				"_id": "7ef64686-976f-4737-aebd-e4aea445202d",
				"_kind": "bookshelf",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_visibility": "protected",
				"_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
				"_ownerGroups": ["group-1"],
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
			"_toMetadata": {
				"_id": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
				"_kind": "book",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_visibility": "protected",
				"_ownerUsers": [],
				"_ownerGroups": [],
				"_viewerUsers": [],
				"_viewerGroups": ["group-1"],
			},
		},
	)
}

# Records scope roles (covers relations specifically)
test_allow_to_records_admin if {
	allow with input as produce_input_doc_by_role(
		"tarcinapp.records.admin", true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
		},
		{
			"_fromMetadata": {
				"_id": "7ef64686-976f-4737-aebd-e4aea445202d",
				"_kind": "bookshelf",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_visibility": "protected",
				"_ownerUsers": ["other-user"],
				"_ownerGroups": [],
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
			"_toMetadata": {
				"_id": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
				"_kind": "book",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_visibility": "public",
				"_ownerUsers": [],
				"_ownerGroups": [],
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
		},
	)
}

test_allow_to_records_editor if {
	allow with input as produce_input_doc_by_role(
		"tarcinapp.records.editor", true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
		},
		{
			"_fromMetadata": {
				"_id": "7ef64686-976f-4737-aebd-e4aea445202d",
				"_kind": "bookshelf",
				"_validFromDateTime": null,
				"_validUntilDateTime": null,
				"_visibility": "private",
				"_ownerUsers": ["other-user"],
				"_ownerGroups": [],
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
			"_toMetadata": {
				"_id": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
				"_kind": "book",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_visibility": "private",
				"_ownerUsers": [],
				"_ownerGroups": [],
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
		},
	)
}

# Relations scope specific roles
test_allow_to_relations_admin if {
	allow with input as produce_input_doc_by_role(
		"tarcinapp.relations.admin", true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
		},
		{
			"_fromMetadata": {"_id": "7ef64686-976f-4737-aebd-e4aea445202d", "_kind": "bookshelf", "_validFromDateTime": null, "_validUntilDateTime": null, "_visibility": "protected", "_ownerUsers": ["other-user"], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
			"_toMetadata": {"_id": "17d4ccba-a726-4b5e-8f75-0cb303eb5131", "_kind": "book", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
		},
	)
}

# ========================================
# GROUP ACCESS AND OWNER VALIDATION TESTS
# ========================================

# Test group access for member roles - owner via _ownerGroups
test_allow_to_global_member_correct_group if {
	allow with input as produce_input_doc_by_role(
		"tarcinapp.member", true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
		},
		{
			"_fromMetadata": {
				"_id": "7ef64686-976f-4737-aebd-e4aea445202d",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_visibility": "protected",
				"_ownerUsers": ["other-user"],
				"_ownerGroups": ["group-1"],
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
			"_toMetadata": {
				"_id": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_visibility": "public",
				"_ownerUsers": [],
				"_ownerGroups": [],
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
		},
	)
}

# Test multiple valid groups for member roles (one of them is user's)
test_allow_to_global_member_multiple_valid_groups if {
	allow with input as produce_input_doc_by_role(
		"tarcinapp.member", true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
		},
		{
			"_fromMetadata": {
				"_id": "7ef64686-976f-4737-aebd-e4aea445202d",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_visibility": "protected",
				"_ownerUsers": [],
				"_ownerGroups": ["group-1", "group-3"],
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
			"_toMetadata": {
				"_id": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_visibility": "public",
				"_ownerUsers": [],
				"_ownerGroups": [],
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
		},
	)
}

# Test no groups provided but direct owner via _ownerUsers (should be allowed)
test_allow_to_global_member_no_groups if {
	allow with input as produce_input_doc_by_role(
		"tarcinapp.member", true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
		},
		{
			"_fromMetadata": {
				"_id": "7ef64686-976f-4737-aebd-e4aea445202d",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_visibility": "public",
				"_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
				"_ownerGroups": [],
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
			"_toMetadata": {
				"_id": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_visibility": "public",
				"_ownerUsers": [],
				"_ownerGroups": [],
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
		},
	)
}

# Test empty ownerGroups array (should be allowed when user is direct owner)
test_allow_to_global_member_empty_groups if {
	allow with input as produce_input_doc_by_role(
		"tarcinapp.member", true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
		},
		{
			"_fromMetadata": {
				"_id": "7ef64686-976f-4737-aebd-e4aea445202d",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_visibility": "public",
				"_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
				"_ownerGroups": [],
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
			"_toMetadata": {
				"_id": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_visibility": "public",
				"_ownerUsers": [],
				"_ownerGroups": [],
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
		},
	)
}

# ========================================
# NEGATIVE TESTS - ROLES AND CONDITIONS THAT SHOULD NOT ALLOW
# ========================================

# Forbidden field tests for editor roles (editors cannot set _createdBy)
test_not_allow_to_global_editor_by_forbidden_field if {
	not allow with input as produce_input_doc_by_role(
		"tarcinapp.editor", true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
			"_createdBy": "some-user",
		},
		{
			"_fromMetadata": {"_id": "7ef64686-976f-4737-aebd-e4aea445202d", "_validFromDateTime": null, "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
			"_toMetadata": {"_id": "17d4ccba-a726-4b5e-8f75-0cb303eb5131", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
		},
	)
}

# Forbidden field tests for member roles (members cannot set _createdBy/_validFrom without field role)
test_not_allow_to_global_member_by_forbidden_field if {
	not allow with input as produce_input_doc_by_role(
		"tarcinapp.member", true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
			"_createdBy": "some-user",
		},
		{
			"_fromMetadata": {"_id": "7ef64686-976f-4737-aebd-e4aea445202d", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "protected", "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
			"_toMetadata": {"_id": "17d4ccba-a726-4b5e-8f75-0cb303eb5131", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
		},
	)
}

# Member must be email verified
test_not_allow_to_global_member_email_verification if {
	not allow with input as produce_input_doc_by_role(
		"tarcinapp.member", false, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
		},
		{
			"_fromMetadata": {"_id": "7ef64686-976f-4737-aebd-e4aea445202d", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
			"_toMetadata": {"_id": "17d4ccba-a726-4b5e-8f75-0cb303eb5131", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
		},
	)
}

# Invalid group (no match in token groups) should deny member
test_not_allow_to_global_member_by_invalid_group if {
	not allow with input as produce_input_doc_by_role(
		"tarcinapp.member", true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
		},
		{
			"_fromMetadata": {"_id": "7ef64686-976f-4737-aebd-e4aea445202d", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "protected", "_ownerUsers": [], "_ownerGroups": ["group-2"], "_viewerUsers": [], "_viewerGroups": []},
			"_toMetadata": {"_id": "17d4ccba-a726-4b5e-8f75-0cb303eb5131", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
		},
	)
}

# Mixed ownerGroups where at least one group belongs to the user should still allow (relation-specific behaviour)
test_allow_to_global_member_by_mixed_groups if {
	allow with input as produce_input_doc_by_role(
		"tarcinapp.member", true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
		},
		{
			"_fromMetadata": {"_id": "7ef64686-976f-4737-aebd-e4aea445202d", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "protected", "_ownerUsers": [], "_ownerGroups": ["group-1", "group-2"], "_viewerUsers": [], "_viewerGroups": []},
			"_toMetadata": {"_id": "17d4ccba-a726-4b5e-8f75-0cb303eb5131", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
		},
	)
}

# Multiple invalid groups - none belong to user -> deny
test_not_allow_to_global_member_by_multiple_invalid_groups if {
	not allow with input as produce_input_doc_by_role(
		"tarcinapp.member", true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
		},
		{
			"_fromMetadata": {"_id": "7ef64686-976f-4737-aebd-e4aea445202d", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "protected", "_ownerUsers": [], "_ownerGroups": ["group-2", "group-4"], "_viewerUsers": [], "_viewerGroups": []},
			"_toMetadata": {"_id": "17d4ccba-a726-4b5e-8f75-0cb303eb5131", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
		},
	)
}

# ========================================
# FIELD-LEVEL ROLE TESTS
# ========================================

# Members allowed to set _validFromDateTime when they have field-level create permission
test_allow_member_with_validFrom_field_permission if {
	allow with input as produce_input_doc_by_role_with_field_permission(
		"tarcinapp.member", true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
			"_validFromDateTime": "2024-01-01T00:00:00Z",
		},
		"tarcinapp.relations.fields._validFromDateTime.create", {
			"_fromMetadata": {"_id": "7ef64686-976f-4737-aebd-e4aea445202d", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
			"_toMetadata": {"_id": "17d4ccba-a726-4b5e-8f75-0cb303eb5131", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
		},
	)
}

# Members allowed to set _validUntilDateTime when they have field-level create permission
test_allow_member_with_validUntil_field_permission if {
	allow with input as produce_input_doc_by_role_with_field_permission(
		"tarcinapp.member", true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
			"_validUntilDateTime": "2026-01-01T00:00:00Z",
		},
		"tarcinapp.relations.fields._validUntilDateTime.create", {
			"_fromMetadata": {"_id": "7ef64686-976f-4737-aebd-e4aea445202d", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
			"_toMetadata": {"_id": "17d4ccba-a726-4b5e-8f75-0cb303eb5131", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
		},
	)
}

# Editors allowed to set forbidden fields when they have field-level permission
test_allow_to_global_editor_with_createdBy_field_permission if {
	allow with input as produce_input_doc_by_role_with_field_permission(
		"tarcinapp.editor", true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
			"_createdBy": "some-user",
		},
		"tarcinapp.relations.fields._createdBy.create", {
			"_fromMetadata": {"_id": "7ef64686-976f-4737-aebd-e4aea445202d", "_validFromDateTime": null, "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
			"_toMetadata": {"_id": "17d4ccba-a726-4b5e-8f75-0cb303eb5131", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
		},
	)
}

# Visitors should NOT be able to create relations even with field-level permission
test_not_allow_to_global_visitor_with_createdBy_field_permission if {
	not allow with input as produce_input_doc_by_role_with_field_permission(
		"tarcinapp.visitor", true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
			"_createdBy": "some-user",
		},
		"tarcinapp.relations.fields._createdBy.create", {
			"_fromMetadata": {"_id": "7ef64686-976f-4737-aebd-e4aea445202d", "_validFromDateTime": null, "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
			"_toMetadata": {"_id": "17d4ccba-a726-4b5e-8f75-0cb303eb5131", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
		},
	)
}

# Wrong scope: field-level permission for entities should NOT allow relation creation
test_not_allow_to_global_member_with_entities_scope_field_permission if {
	not allow with input as produce_input_doc_by_role_with_field_permission(
		"tarcinapp.member", true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
			"_validFromDateTime": "2024-01-01T00:00:00Z",
		},
		"tarcinapp.entities.fields._validFromDateTime.create", {
			"_fromMetadata": {"_id": "7ef64686-976f-4737-aebd-e4aea445202d", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
			"_toMetadata": {"_id": "17d4ccba-a726-4b5e-8f75-0cb303eb5131", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
		},
	)
}

# Wrong operation: find-only field permission should NOT allow create
test_not_allow_to_global_member_with_find_only_field_permission if {
	not allow with input as produce_input_doc_by_role_with_field_permission(
		"tarcinapp.member", true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
			"_validFromDateTime": "2024-01-01T00:00:00Z",
		},
		"tarcinapp.relations.fields._validFromDateTime.find", {
			"_fromMetadata": {"_id": "7ef64686-976f-4737-aebd-e4aea445202d", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
			"_toMetadata": {"_id": "17d4ccba-a726-4b5e-8f75-0cb303eb5131", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
		},
	)
}

# ========================================
# REFERENCED LIST & CITED ENTITY VALIDATION TESTS
# ========================================

# Referenced list must have validFrom set and in the past
test_not_allow_member_when_referenced_list_has_no_validFrom if {
	not allow with input as produce_input_doc_by_role(
		"tarcinapp.member", true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
		},
		{
			"_fromMetadata": {"_id": "7ef64686-976f-4737-aebd-e4aea445202d", "_validFromDateTime": null, "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
			"_toMetadata": {"_id": "17d4ccba-a726-4b5e-8f75-0cb303eb5131", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
		},
	)
}

# Referenced list which is passive (validUntil in the past) should deny
test_not_allow_member_when_referenced_list_is_passive if {
	not allow with input as produce_input_doc_by_role(
		"tarcinapp.member", true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
		},
		{
			"_fromMetadata": {"_id": "7ef64686-976f-4737-aebd-e4aea445202d", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": "2021-01-01T00:00:00Z", "_visibility": "public", "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
			"_toMetadata": {"_id": "17d4ccba-a726-4b5e-8f75-0cb303eb5131", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
		},
	)
}

# Entity must be active even if caller owns it directly
test_not_allow_member_when_entity_pending_even_if_owner_user if {
	not allow with input as produce_input_doc_by_role(
		"tarcinapp.member", true, {
			"_kind": "contains",
			"_listId": "list-a1",
			"_entityId": "entity-a1",
		},
		{
			"_fromMetadata": {"_id": "list-a1", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
			"_toMetadata": {"_id": "entity-a1", "_validFromDateTime": null, "_validUntilDateTime": null, "_visibility": "protected", "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
		},
	)
}

# Entity must be active even if caller owns via group (non-private)
test_not_allow_member_when_entity_pending_even_if_owner_group if {
	not allow with input as produce_input_doc_by_role(
		"tarcinapp.member", true, {
			"_kind": "contains",
			"_listId": "list-a2",
			"_entityId": "entity-a2",
		},
		{
			"_fromMetadata": {"_id": "list-a2", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "protected", "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
			"_toMetadata": {"_id": "entity-a2", "_validFromDateTime": null, "_validUntilDateTime": null, "_visibility": "protected", "_ownerUsers": [], "_ownerGroups": ["group-1"], "_viewerUsers": [], "_viewerGroups": []},
		},
	)
}

# Cited entity must be active and visible to caller
test_allow_member_if_entity_public_and_active if {
	allow with input as produce_input_doc_by_role(
		"tarcinapp.member", true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
		},
		{
			"_fromMetadata": {"_id": "7ef64686-976f-4737-aebd-e4aea445202d", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
			"_toMetadata": {"_id": "17d4ccba-a726-4b5e-8f75-0cb303eb5131", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
		},
	)
}

# Cited entity private and caller not owner/viewer should deny
test_not_allow_member_if_entity_private_and_not_owner if {
	not allow with input as produce_input_doc_by_role(
		"tarcinapp.member", true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
		},
		{
			"_fromMetadata": {"_id": "7ef64686-976f-4737-aebd-e4aea445202d", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
			"_toMetadata": {"_id": "17d4ccba-a726-4b5e-8f75-0cb303eb5131", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "private", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
		},
	)
}

# Cited entity view permissions allow members
test_allow_member_if_entity_has_viewer_user if {
	allow with input as produce_input_doc_by_role(
		"tarcinapp.member", true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
		},
		{
			"_fromMetadata": {"_id": "7ef64686-976f-4737-aebd-e4aea445202d", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
			"_toMetadata": {"_id": "17d4ccba-a726-4b5e-8f75-0cb303eb5131", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "protected", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_viewerGroups": []},
		},
	)
}

test_allow_member_if_entity_has_viewer_group if {
	allow with input as produce_input_doc_by_role(
		"tarcinapp.member", true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
		},
		{
			"_fromMetadata": {"_id": "7ef64686-976f-4737-aebd-e4aea445202d", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
			"_toMetadata": {"_id": "17d4ccba-a726-4b5e-8f75-0cb303eb5131", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "protected", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": ["group-1"]},
		},
	)
}

# ========================================
# VISIBILITY / SCOPE NEGATIVE AND CROSS-SCOPE TESTS
# ========================================

# Visitor role tests (should not allow creation)
test_not_allow_to_global_visitor if {
	not allow with input as produce_input_doc_by_role(
		"tarcinapp.visitor", true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
		},
		{
			"_fromMetadata": {"_id": "7ef64686-976f-4737-aebd-e4aea445202d", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
			"_toMetadata": {"_id": "17d4ccba-a726-4b5e-8f75-0cb303eb5131", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
		},
	)
}

# Cross-scope role tests (entity/list scoped roles should not allow relation create)
test_not_allow_to_entities_admin if {
	not allow with input as produce_input_doc_by_role(
		"tarcinapp.entities.admin", true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
		},
		{
			"_fromMetadata": {"_id": "7ef64686-976f-4737-aebd-e4aea445202d", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
			"_toMetadata": {"_id": "17d4ccba-a726-4b5e-8f75-0cb303eb5131", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
		},
	)
}

test_not_allow_to_lists_admin if {
	not allow with input as produce_input_doc_by_role(
		"tarcinapp.lists.admin", true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
		},
		{
			"_fromMetadata": {"_id": "7ef64686-976f-4737-aebd-e4aea445202d", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
			"_toMetadata": {"_id": "17d4ccba-a726-4b5e-8f75-0cb303eb5131", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
		},
	)
}

# Cross-operation role tests (find/update only roles should not allow create)
test_not_allow_to_relations_find_admin if {
	not allow with input as produce_input_doc_by_role(
		"tarcinapp.relations.find.admin", true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
		},
		{
			"_fromMetadata": {"_id": "7ef64686-976f-4737-aebd-e4aea445202d", "_validFromDateTime": null, "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
			"_toMetadata": {"_id": "17d4ccba-a726-4b5e-8f75-0cb303eb5131", "_validFromDateTime": null, "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
		},
	)
}

test_not_allow_to_relations_update_admin if {
	not allow with input as produce_input_doc_by_role(
		"tarcinapp.relations.update.admin", true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
		},
		{
			"_fromMetadata": {"_id": "7ef64686-976f-4737-aebd-e4aea445202d", "_validFromDateTime": null, "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
			"_toMetadata": {"_id": "17d4ccba-a726-4b5e-8f75-0cb303eb5131", "_validFromDateTime": null, "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
		},
	)
}

# Helper function to create test input with metadata in requestPayload
produce_input_doc_by_role(roles, is_email_verified, requestPayload, metadata) := test_body if {
	# Merge the base requestPayload with metadata
	merged_payload := object.union(requestPayload, metadata)

	test_body = {
		"appShortcode": "tarcinapp",
		"httpMethod": "POST",
		"requestPath": "/relations",
		"queryParams": {},
		"encodedJwt": test.produce_token({
			"sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
			"name": "John Doe",
			"admin": true,
			"iat": 1516239022,
			"email_verified": is_email_verified,
			"groups": ["group-1", "group-3"],
			"roles": [roles],
		}),
		"requestPayload": merged_payload,
	}
}

# Helper function to create test input with field-level permission and metadata in requestPayload
produce_input_doc_by_role_with_field_permission(roles, is_email_verified, requestPayload, fieldPermission, metadata) := test_body if {
	# Merge the base requestPayload with metadata
	merged_payload := object.union(requestPayload, metadata)

	test_body = {
		"appShortcode": "tarcinapp",
		"httpMethod": "POST",
		"requestPath": "/relations",
		"queryParams": {},
		"encodedJwt": test.produce_token({
			"sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
			"name": "John Doe",
			"admin": true,
			"iat": 1516239022,
			"email_verified": is_email_verified,
			"groups": ["group-1", "group-3"],
			"roles": [roles, fieldPermission],
		}),
		"requestPayload": merged_payload,
	}
}
