package policies.auth.routes.relations.updateRelationById.policy

import data.policies.fields.relations.policy as forbidden_fields
import data.policies.util.common.test as test

# Helper for relation update (PATCH) tests
produce_input_update(roles, is_email_verified, userGroups, requestPayload, originalRecord) := test_body if {
	test_body = {
		"appShortcode": "tarcinapp",
		"httpMethod": "PATCH",
		"requestPath": "/relations",
		"queryParams": {},
		"encodedJwt": test.produce_token({
			"sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
			"name": "John Doe",
			"admin": true,
			"iat": 1516239022,
			"email_verified": is_email_verified,
			"groups": userGroups,
			"roles": roles,
		}),
		"requestPayload": requestPayload,
		"originalRecord": originalRecord,
	}
}

# -------------------------
# Admin / Editor basics
# -------------------------

test_allow_admin_verified_minimal_payload if {
	allow with input as produce_input_update(
		["tarcinapp.admin"],
		true, [], {}, {
			"_listId": "admin-list-1",
			"_entityId": "admin-entity-1",
			"_fromMetadata": {"_id": "admin-list-1", "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
			"_toMetadata": {"_id": "admin-entity-1", "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
		},
	)
}

test_not_allow_admin_not_verified if {
	not allow with input as produce_input_update(
		["tarcinapp.admin"],
		false, [], {}, {
			"_listId": "admin-list-1",
			"_entityId": "admin-entity-1",
			"_fromMetadata": {"_id": "admin-list-1", "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
			"_toMetadata": {"_id": "admin-entity-1", "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
		},
	)
}

test_allow_admin_with_all_fields if {
	allow with input as produce_input_update(
		["tarcinapp.admin"],
		true, [], {
			"_listId": "admin-list-2",
			"_entityId": "admin-entity-2",
			"_createdDateTime": "2024-01-01T00:00:00Z",
			"_lastUpdatedDateTime": "2024-02-01T00:00:00Z",
			"_idempotencyKey": "admin-key",
			"_version": 42,
			"_application": "test-app",
		},
		{
			"_listId": "admin-list-2",
			"_entityId": "admin-entity-2",
			"_kind": "contains",
			"_fromMetadata": {"_id": "admin-list-2", "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
			"_toMetadata": {"_id": "admin-entity-2", "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
		},
	)
}

test_allow_editor_leave_forbidden_update_field_unchanged if {
	allow with input as produce_input_update(
		["tarcinapp.editor"],
		true, [], {
			"_listId": "list-e1",
			"_entityId": "entity-e1",
			"_createdDateTime": "2022-01-01T00:00:00Z",
		},
		{
			"_listId": "list-e1",
			"_entityId": "entity-e1",
			"_kind": "contains",
			"_createdDateTime": "2022-01-01T00:00:00Z",
			"_fromMetadata": {"_id": "list-e1", "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
			"_toMetadata": {"_id": "entity-e1", "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
		},
	)
}

test_not_allow_editor_change_forbidden_update_field if {
	not allow with input as produce_input_update(
		["tarcinapp.editor"],
		true, [], {
			"_listId": "list-e2",
			"_entityId": "entity-e2",
			"_createdDateTime": "2023-01-01T00:00:00Z", # changed compared to original
		},
		{
			"_listId": "list-e2",
			"_entityId": "entity-e2",
			"_kind": "contains",
			"_createdDateTime": "2022-01-01T00:00:00Z",
			"_fromMetadata": {"_id": "list-e2", "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
			"_toMetadata": {"_id": "entity-e2", "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
		},
	)
}

test_allow_editor_retarget_ids_on_patch if {
	allow with input as produce_input_update(
		["tarcinapp.editor"],
		true, [], {
			"_listId": "different-list",
			"_entityId": "entity-e3",
		},
		{
			"_listId": "list-e3",
			"_entityId": "entity-e3",
			"_kind": "contains",
			"_fromMetadata": {"_id": "list-e3", "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
			"_toMetadata": {"_id": "entity-e3", "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
		},
	)
}

# -------------------------
# Member tests
# -------------------------

test_allow_member_owner_and_viewer_private_entity_with_patch if {
	allow with input as produce_input_update(
		["tarcinapp.member"],
		true, [], {
			"_listId": "m-list-1",
			"_entityId": "m-entity-1",
			"note": "member update",
		},
		{
			"_listId": "m-list-1",
			"_entityId": "m-entity-1",
			"_kind": "contains",
			"_fromMetadata": {"_id": "m-list-1", "_visibility": "protected", "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
			"_toMetadata": {"_id": "m-entity-1", "_visibility": "private", "_viewerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_viewerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
		},
	)
}

# Test: member owns the referenced list through ownerGroups, can see the target
# protected entity via viewerGroups, and tries to introduce a forbidden-for-update
# field (`_createdDateTime`) in a PATCH — should be denied.
test_not_allow_member_introduce_forbidden_update_field_via_patch_if_ownergroup_and_viewergroup if {
	not allow with input as produce_input_update(
		["tarcinapp.member"], true, ["owner-group", "viewer-group"],
		{
			"_listId": "list-123",
			"_entityId": "entity-456",
			"_createdDateTime": "2025-01-01T00:00:00Z", # forbidden-for-update for members and not present in original
		},
		{
			"_listId": "list-123",
			"_entityId": "entity-456",
			"_kind": "contains",
			"_fromMetadata": {
				"_id": "list-123",
				"_kind": "bookshelf",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_visibility": "protected",
				"_ownerUsers": [],
				"_ownerGroups": ["owner-group"],
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
			"_toMetadata": {
				"_id": "entity-456",
				"_kind": "book",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_visibility": "protected",
				"_ownerUsers": [],
				"_ownerGroups": [],
				"_viewerUsers": [],
				"_viewerGroups": ["viewer-group"],
			},
		},
	)
}

test_allow_member_ownervia_user_private_list_and_see_public_entity_with_patch if {
	allow with input as produce_input_update(
		["tarcinapp.member"], true, [],
		{
			"_listId": "list-123",
			"_entityId": "entity-456",
			"note": "adding a note",
		},
		{
			"_listId": "list-123",
			"_entityId": "entity-456",
			"_kind": "contains",
			"_fromMetadata": {
				"_id": "list-123",
				"_kind": "bookshelf",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_visibility": "private",
				"_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
				"_ownerGroups": [],
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
			"_toMetadata": {
				"_id": "entity-456",
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

test_not_allow_member_not_verified if {
	not allow with input as produce_input_update(
		["tarcinapp.member"],
		false, [], {
			"_listId": "m-list-2",
			"_entityId": "m-entity-2",
		},
		{
			"_listId": "m-list-2",
			"_entityId": "m-entity-2",
			"_kind": "contains",
			"_fromMetadata": {"_id": "m-list-2", "_visibility": "public", "_ownerUsers": ["other-user"], "_ownerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
			"_toMetadata": {"_id": "m-entity-2", "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
		},
	)
}

test_not_allow_member_not_owner_of_list if {
	not allow with input as produce_input_update(
		["tarcinapp.member"],
		true, ["some-group"], {
			"_listId": "m-list-3",
			"_entityId": "m-entity-3",
		},
		{
			"_listId": "m-list-3",
			"_entityId": "m-entity-3",
			"_kind": "contains",
			"_fromMetadata": {"_id": "m-list-3", "_visibility": "protected", "_ownerUsers": ["other-user"], "_ownerGroups": ["other-group"], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
			"_toMetadata": {"_id": "m-entity-3", "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
		},
	)
}

test_not_allow_member_cannot_see_target_entity if {
	not allow with input as produce_input_update(
		["tarcinapp.member"],
		true, [], {
			"_listId": "m-list-4",
			"_entityId": "m-entity-private",
		},
		{
			"_listId": "m-list-4",
			"_entityId": "m-entity-private",
			"_kind": "contains",
			"_fromMetadata": {"_id": "m-list-4", "_visibility": "public", "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
			"_toMetadata": {"_id": "m-entity-private", "_visibility": "private", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
		},
	)
}

test_not_allow_member_change_listId if {
	not allow with input as produce_input_update(
		["tarcinapp.member"],
		true, [], {
			"_listId": "retargeted-list",
			"_entityId": "m-entity-5",
		},
		{
			"_listId": "m-list-5",
			"_entityId": "m-entity-5",
			"_kind": "contains",
			"_fromMetadata": {"_id": "m-list-5", "_visibility": "public", "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
			"_toMetadata": {"_id": "m-entity-5", "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
		},
	)
}

test_not_allow_member_change_entityId if {
	not allow with input as produce_input_update(
		["tarcinapp.member"],
		true, [], {
			"_listId": "m-list-6",
			"_entityId": "different-entity",
		},
		{
			"_listId": "m-list-6",
			"_entityId": "m-entity-6",
			"_kind": "contains",
			"_fromMetadata": {"_id": "m-list-6", "_visibility": "public", "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
			"_toMetadata": {"_id": "m-entity-6", "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
		},
	)
}

test_not_allow_member_introduce_forbidden_update_field_when_original_missing if {
	not allow with input as produce_input_update(
		["tarcinapp.member"],
		true, [], {
			"_listId": "m-list-7",
			"_entityId": "m-entity-7",
			"_createdDateTime": "2025-01-01T00:00:00Z", # forbidden for member updates when original did not have it
		},
		{
			"_listId": "m-list-7",
			"_entityId": "m-entity-7",
			"_kind": "contains",
			"_fromMetadata": {"_id": "m-list-7", "_visibility": "protected", "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
			"_toMetadata": {"_id": "m-entity-7", "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
		},
	)
}

test_allow_member_introduce_forbidden_update_field_with_field_role_validFrom if {
	now := time.now_ns() / 1000000000
	validFrom := now - 80
	validFromStr := time.format([validFrom * 1000000000, "UTC", "RFC3339"])

	allow with input as produce_input_update(
		[
			"tarcinapp.member",
			"tarcinapp.relations.fields._validFromDateTime.update",
		],
		true, [], {
			"_listId": "m-list-8",
			"_entityId": "m-entity-8",
			"_validFromDateTime": validFromStr,
		},
		{
			"_listId": "m-list-8",
			"_entityId": "m-entity-8",
			"_kind": "contains",
			"_fromMetadata": {"_id": "m-list-8", "_visibility": "protected", "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_validFromDateTime": null, "_validUntilDateTime": null},
			"_toMetadata": {"_id": "m-entity-8", "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
		},
	)
}

test_not_allow_member_set_validFrom_out_of_range_with_field_role if {
	# Use a fixed timestamp far in the past to avoid timing/race issues
	validFromStr := "2000-01-01T00:00:00Z"

	not allow with input as produce_input_update(
		[
			"tarcinapp.member",
			"tarcinapp.relations.fields._validFromDateTime.update",
		],
		true, [], {
			"_listId": "m-list-9",
			"_entityId": "m-entity-9",
			"_validFromDateTime": validFromStr,
		},
		{
			"_listId": "m-list-9",
			"_entityId": "m-entity-9",
			"_kind": "contains",
			"_validFromDateTime": null,
			"_fromMetadata": {"_id": "m-list-9", "_visibility": "protected", "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_validFromDateTime": null, "_validUntilDateTime": null},
			"_toMetadata": {"_id": "m-entity-9", "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
		},
	)
}

# Same scenario but the original top-level validity fields are explicitly present and null.
test_not_allow_member_set_validFrom_out_of_range_with_field_role_when_original_has_nulls if {
	# Use a fixed timestamp far in the past to avoid timing/race issues
	validFromStr := "2000-01-01T00:00:00Z"

	not allow with input as produce_input_update(
		[
			"tarcinapp.member",
			"tarcinapp.relations.fields._validFromDateTime.update",
		],
		true, [], {
			"_listId": "m-list-9b",
			"_entityId": "m-entity-9b",
			"_validFromDateTime": validFromStr,
		},
		{
			"_listId": "m-list-9b",
			"_entityId": "m-entity-9b",
			"_kind": "contains",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"_fromMetadata": {"_id": "m-list-9b", "_visibility": "protected", "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_validFromDateTime": null, "_validUntilDateTime": null},
			"_toMetadata": {"_id": "m-entity-9b", "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
		},
	)
}

# Debug tests to help reason about the failing case

test_allow_member_set_validUntil_with_field_role if {
	now := time.now_ns() / 1000000000
	validUntil := now - 1
	validUntilStr := time.format([validUntil * 1000000000, "UTC", "RFC3339"])

	allow with input as produce_input_update(
		[
			"tarcinapp.member",
			"tarcinapp.relations.fields._validUntilDateTime.update",
		],
		true, [], {
			"_listId": "m-list-10",
			"_entityId": "m-entity-10",
			"_validUntilDateTime": validUntilStr,
		},
		{
			"_listId": "m-list-10",
			"_entityId": "m-entity-10",
			"_kind": "contains",
			"_fromMetadata": {"_id": "m-list-10", "_visibility": "protected", "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_validFromDateTime": null, "_validUntilDateTime": null},
			"_toMetadata": {"_id": "m-entity-10", "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
		},
	)
}

test_not_allow_member_set_validUntil_out_of_range_with_field_role if {
	now := time.now_ns() / 1000000000
	validUntil := now - 400
	validUntilStr := time.format([validUntil * 1000000000, "UTC", "RFC3339"])

	not allow with input as produce_input_update(
		[
			"tarcinapp.member",
			"tarcinapp.relations.fields._validUntilDateTime.update",
		],
		true, [], {
			"_listId": "m-list-11",
			"_entityId": "m-entity-11",
			"_validUntilDateTime": validUntilStr,
		},
		{
			"_listId": "m-list-11",
			"_entityId": "m-entity-11",
			"_kind": "contains",
			"_fromMetadata": {"_id": "m-list-11", "_visibility": "protected", "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_validFromDateTime": null, "_validUntilDateTime": null},
			"_toMetadata": {"_id": "m-entity-11", "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
		},
	)
}

# Same scenario but the original top-level validity fields are explicitly present and null.
test_not_allow_member_set_validUntil_out_of_range_with_field_role_when_original_has_nulls if {
	now := time.now_ns() / 1000000000
	validUntil := now - 400
	validUntilStr := time.format([validUntil * 1000000000, "UTC", "RFC3339"])

	not allow with input as produce_input_update(
		[
			"tarcinapp.member",
			"tarcinapp.relations.fields._validUntilDateTime.update",
		],
		true, [], {
			"_listId": "m-list-11b",
			"_entityId": "m-entity-11b",
			"_validUntilDateTime": validUntilStr,
		},
		{
			"_listId": "m-list-11b",
			"_entityId": "m-entity-11b",
			"_kind": "contains",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"_fromMetadata": {"_id": "m-list-11b", "_visibility": "protected", "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_validFromDateTime": null, "_validUntilDateTime": null},
			"_toMetadata": {"_id": "m-entity-11b", "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
		},
	)
}

test_allow_member_omit_forbidden_update_field_when_original_has_value if {
	allow with input as produce_input_update(
		["tarcinapp.member"],
		true, [], {
			"_listId": "m-list-12",
			"_entityId": "m-entity-12",
			"note": "no createdDateTime in payload",
		},
		{
			"_listId": "m-list-12",
			"_entityId": "m-entity-12",
			"_kind": "contains",
			"_createdDateTime": "2020-01-01T00:00:00Z",
			"_fromMetadata": {"_id": "m-list-12", "_visibility": "protected", "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
			"_toMetadata": {"_id": "m-entity-12", "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
		},
	)
}

test_not_allow_member_change_forbidden_update_field_when_original_has_value if {
	not allow with input as produce_input_update(
		["tarcinapp.member"],
		true, [], {
			"_listId": "m-list-13",
			"_entityId": "m-entity-13",
			"_createdDateTime": "2022-01-01T00:00:00Z", # different than original
		},
		{
			"_listId": "m-list-13",
			"_entityId": "m-entity-13",
			"_kind": "contains",
			"_createdDateTime": "2020-01-01T00:00:00Z",
			"_fromMetadata": {"_id": "m-list-13", "_visibility": "protected", "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
			"_toMetadata": {"_id": "m-entity-13", "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
		},
	)
}

# -------------------------
# Forbidden-to-see enforcement
# -------------------------

test_not_allow_member_include_forbidden_to_see_field_in_payload if {
	not allow with input as produce_input_update(
		["tarcinapp.member"],
		true, [], {
			"_listId": "m-list-14",
			"_entityId": "m-entity-14",
			"_idempotencyKey": "should-be-forbidden",
		},
		{
			"_listId": "m-list-14",
			"_entityId": "m-entity-14",
			"_kind": "contains",
			"_fromMetadata": {"_id": "m-list-14", "_visibility": "public", "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
			"_toMetadata": {"_id": "m-entity-14", "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
		},
	)
}

test_admin_can_include_member_forbidden_fields if {
	allow with input as produce_input_update(
		["tarcinapp.admin"],
		true, [], {
			"_listId": "admin-list-3",
			"_entityId": "admin-entity-3",
			"_idempotencyKey": "admin-allowed",
		},
		{
			"_listId": "admin-list-3",
			"_entityId": "admin-entity-3",
			"_kind": "contains",
			"_fromMetadata": {"_id": "admin-list-3", "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
			"_toMetadata": {"_id": "admin-entity-3", "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
		},
	)
}

# -------------------------
# Passive / missing metadata edge cases
# -------------------------

test_not_allow_member_update_passive_relation if {
	not allow with input as produce_input_update(
		["tarcinapp.member"],
		true, [], {
			"_listId": "m-list-15",
			"_entityId": "m-entity-15",
			"note": "attempt on passive",
		},
		{
			"_listId": "m-list-15",
			"_entityId": "m-entity-15",
			"_kind": "contains",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": "2020-02-01T00:00:00Z", # passive because in the past
			"_fromMetadata": {"_id": "m-list-15", "_visibility": "public", "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": "2020-02-01T00:00:00Z"},
			"_toMetadata": {"_id": "m-entity-15", "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
		},
	)
}

test_not_allow_missing_original_record if {
	test_body = {
		"appShortcode": "tarcinapp",
		"httpMethod": "PATCH",
		"requestPath": "/relations",
		"queryParams": {},
		"encodedJwt": test.produce_token({
			"sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
			"name": "John Doe",
			"admin": true,
			"iat": 1516239022,
			"email_verified": true,
			"groups": [],
			"roles": ["tarcinapp.member"],
		}),
		"requestPayload": {"_listId": "no-original-list", "_entityId": "no-original-entity"},
	}

	not allow with input as test_body
}

test_not_allow_missing_from_or_to_metadata if {
	not allow with input as produce_input_update(
		["tarcinapp.member"],
		true, [], {
			"_listId": "m-list-16",
			"_entityId": "m-entity-16",
		},
		{
			"_listId": "m-list-16",
			"_entityId": "m-entity-16",
			"_kind": "contains",
			# purposely missing _fromMetadata
			"_toMetadata": {"_id": "m-entity-16", "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
		},
	)

	not allow with input as produce_input_update(
		["tarcinapp.member"],
		true, [], {
			"_listId": "m-list-17",
			"_entityId": "m-entity-17",
		},
		{
			"_listId": "m-list-17",
			"_entityId": "m-entity-17",
			"_kind": "contains",
			"_fromMetadata": {"_id": "m-list-17", "_visibility": "public", "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
			# purposely missing _toMetadata
		},
	)
}

# -------------------------
# Visitor
# -------------------------

test_not_allow_visitor_even_with_field_roles if {
	not allow with input as produce_input_update(
		[
			"tarcinapp.visitor",
			"tarcinapp.relations.fields._validFromDateTime.update",
		],
		true, [], {
			"_listId": "m-list-18",
			"_entityId": "m-entity-18",
			"_validFromDateTime": "2024-01-01T00:00:00Z",
		},
		{
			"_listId": "m-list-18",
			"_entityId": "m-entity-18",
			"_kind": "contains",
			"_fromMetadata": {"_id": "m-list-18", "_visibility": "public", "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
			"_toMetadata": {"_id": "m-entity-18", "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
		},
	)
}
