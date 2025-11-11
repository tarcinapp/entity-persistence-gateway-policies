package policies.auth.routes.relations.replaceRelationById.policy

import data.policies.util.common.test as test

# Helper for relation replace tests
produce_input_replace(roles, is_email_verified, requestPayload, originalRecord) := test_body if {
	test_body = {
		"appShortcode": "tarcinapp",
		"httpMethod": "PUT",
		"requestPath": "/relations",
		"queryParams": {},
		"encodedJwt": test.produce_token({
			"sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
			"name": "John Doe",
			"admin": true,
			"iat": 1516239022,
			"email_verified": is_email_verified,
			"groups": ["group-1", "group-3"],
			"roles": roles,
		}),
		"requestPayload": requestPayload,
		"originalRecord": originalRecord,
	}
}

# ==========================
# Admin / Editor test cases
# ==========================

test_allow_admin_verified if {
	allow with input as produce_input_replace(
		["tarcinapp.admin"], true, {
			"_kind": "contains",
			"_listId": "list-1",
			"_entityId": "entity-1",
		},
		{
			"_kind": "contains",
			"_listId": "list-1",
			"_entityId": "entity-1",
			"_fromMetadata": {"_ownerUsers": ["other-user"], "_ownerGroups": []},
			"_toMetadata": {"_ownerUsers": [], "_ownerGroups": [], "_visibility": "public", "_validFromDateTime": "2020-01-01T00:00:00Z"},
		},
	)
}

test_not_allow_admin_not_verified if {
	not allow with input as produce_input_replace(
		["tarcinapp.admin"], false, {
			"_kind": "contains",
			"_listId": "list-1",
			"_entityId": "entity-1",
		},
		{
			"_kind": "contains",
			"_listId": "list-1",
			"_entityId": "entity-1",
			"_fromMetadata": {"_ownerUsers": ["other-user"], "_ownerGroups": []},
			"_toMetadata": {"_ownerUsers": [], "_ownerGroups": [], "_visibility": "public", "_validFromDateTime": "2020-01-01T00:00:00Z"},
		},
	)
}

test_allow_editor_verified if {
	allow with input as produce_input_replace(
		["tarcinapp.editor"], true, {
			"_kind": "contains",
			"_listId": "list-1",
			"_entityId": "entity-1",
			"_createdDateTime": "2022-01-01T00:00:00Z",
		},
		{
			"_kind": "contains",
			"_listId": "list-1",
			"_entityId": "entity-1",
			"_createdDateTime": "2022-01-01T00:00:00Z",
			"_fromMetadata": {"_ownerUsers": ["other-user"], "_ownerGroups": []},
			"_toMetadata": {"_ownerUsers": [], "_ownerGroups": [], "_visibility": "public", "_validFromDateTime": "2020-01-01T00:00:00Z"},
		},
	)
}

test_not_allow_editor_not_verified if {
	not allow with input as produce_input_replace(
		["tarcinapp.editor"], false, {
			"_kind": "contains",
			"_listId": "list-1",
			"_entityId": "entity-1",
		},
		{
			"_kind": "contains",
			"_listId": "list-1",
			"_entityId": "entity-1",
			"_fromMetadata": {"_ownerUsers": ["other-user"], "_ownerGroups": []},
			"_toMetadata": {"_ownerUsers": [], "_ownerGroups": [], "_visibility": "public", "_validFromDateTime": "2020-01-01T00:00:00Z"},
		},
	)
}

# Editor changing a forbidden update field must be denied (unless it's unchanged)
test_not_allow_editor_change_createdDateTime if {
	not allow with input as produce_input_replace(
		["tarcinapp.editor"], true, {
			"_kind": "contains",
			"_listId": "list-1",
			"_entityId": "entity-1",
			"_createdDateTime": "2023-01-01T00:00:00Z", # different than original
		},
		{
			"_kind": "contains",
			"_listId": "list-1",
			"_entityId": "entity-1",
			"_createdDateTime": "2022-01-01T00:00:00Z",
			"_fromMetadata": {"_ownerUsers": [], "_ownerGroups": []},
			"_toMetadata": {"_ownerUsers": [], "_ownerGroups": [], "_visibility": "public", "_validFromDateTime": "2020-01-01T00:00:00Z"},
		},
	)
}

test_allow_editor_leave_createdDateTime_unchanged if {
	allow with input as produce_input_replace(
		["tarcinapp.editor"], true, {
			"_kind": "contains",
			"_listId": "list-1",
			"_entityId": "entity-1",
			"_createdDateTime": "2022-01-01T00:00:00Z",
		},
		{
			"_kind": "contains",
			"_listId": "list-1",
			"_entityId": "entity-1",
			"_createdDateTime": "2022-01-01T00:00:00Z",
			"_fromMetadata": {"_ownerUsers": [], "_ownerGroups": []},
			"_toMetadata": {"_ownerUsers": [], "_ownerGroups": [], "_visibility": "public", "_validFromDateTime": "2020-01-01T00:00:00Z"},
		},
	)
}

# ==========================
# Member test cases
# ==========================

# Positive test: member owns the referenced list and sees the target entity via viewerUsers
# The target entity is private and active; viewerUsers are permitted to see private active records.
test_allow_member_owner_and_viewer_private_entity if {
	allow with input as produce_input_replace(
		["tarcinapp.member"],
		true, {
			# The replace request should include fields the caller can see. Use the original values
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
			"_validFromDateTime": "2024-01-01T00:00:00Z",
			"_validUntilDateTime": null,
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
				"_name": "Private Book",
				"_slug": "private-book",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_visibility": "private",
				"_ownerUsers": [],
				"_ownerGroups": [],
				"_viewerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
				"_viewerGroups": [],
			},
		},
		{
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
			"_kind": "contains",
			"_validFromDateTime": "2024-01-01T00:00:00Z",
			"_validUntilDateTime": null,
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
				"_name": "Private Book",
				"_slug": "private-book",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_visibility": "public",
				"_ownerUsers": [],
				"_ownerGroups": [],
				"_viewerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
				"_viewerGroups": [],
			},
		},
	)
}

# Negative test: member tries to remove _validFromDateTime/_validUntilDateTime from request
# while they are present in the original record. This must be denied
test_not_allow_member_remove_valid_times if {
	not allow with input as produce_input_replace(
		["tarcinapp.member"],
		true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
			# intentionally omit _validFromDateTime and _validUntilDateTime to simulate removal
		},
		{
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "17d4ccba-a726-4b5e-8f75-0cb303eb5131",
			"_kind": "contains",
			"_validFromDateTime": "2024-01-01T00:00:00Z",
			"_validUntilDateTime": null,
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
				"_name": "Private Book",
				"_slug": "private-book",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_visibility": "private",
				"_ownerUsers": [],
				"_ownerGroups": [],
				"_viewerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
				"_viewerGroups": [],
			},
		},
	)
}

test_allow_member_set_validFrom_with_field_role if {
	now := time.now_ns() / 1000000000
	validFrom := now - 80
	validFromStr := time.format([validFrom * 1000000000, "UTC", "RFC3339"])

	allow with input as produce_input_replace(
		[
			"tarcinapp.member",
			"tarcinapp.relations.fields._validFromDateTime.update",
		],
		true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "entity-1",
			"_validFromDateTime": validFromStr,
		},
		{
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "entity-1",
			"_validFromDateTime": null,
			"_fromMetadata": {"_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_visibility": "protected", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
			"_toMetadata": {"_ownerUsers": [], "_ownerGroups": [], "_visibility": "public", "_validFromDateTime": "2020-01-01T00:00:00Z"},
		},
	)
}

test_allow_member_set_validUntil_with_field_role if {
	now := time.now_ns() / 1000000000
	validUntil := now - 1
	validUntilStr := time.format([validUntil * 1000000000, "UTC", "RFC3339"])

	allow with input as produce_input_replace(
		[
			"tarcinapp.member",
			"tarcinapp.relations.fields._validUntilDateTime.update",
		],
		true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "entity-1",
			"_validUntilDateTime": validUntilStr,
		},
		{
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "entity-1",
			"_validUntilDateTime": null,
			"_fromMetadata": {"_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_visibility": "protected", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
			"_toMetadata": {"_ownerUsers": [], "_ownerGroups": [], "_visibility": "public", "_validFromDateTime": "2020-01-01T00:00:00Z"},
		},
	)
}

test_not_allow_member_not_verified if {
	not allow with input as produce_input_replace(
		["tarcinapp.member"], false, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "entity-1",
		},
		{
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "entity-1",
			"_fromMetadata": {"_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": []},
			"_toMetadata": {"_ownerUsers": [], "_ownerGroups": [], "_visibility": "public", "_validFromDateTime": "2020-01-01T00:00:00Z"},
		},
	)
}

test_not_allow_member_not_owner_of_list if {
	not allow with input as produce_input_replace(
		["tarcinapp.member"], true, {
			"_kind": "contains",
			"_listId": "list-not-owned",
			"_entityId": "entity-1",
		},
		{
			"_kind": "contains",
			"_listId": "list-not-owned",
			"_entityId": "entity-1",
			"_fromMetadata": {"_ownerUsers": ["other-user"], "_ownerGroups": ["other-group"]},
			"_toMetadata": {"_ownerUsers": [], "_ownerGroups": [], "_visibility": "public", "_validFromDateTime": "2020-01-01T00:00:00Z"},
		},
	)
}

test_not_allow_member_cannot_see_target_entity if {
	not allow with input as produce_input_replace(
		["tarcinapp.member"], true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "entity-private",
		},
		{
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "entity-private",
			"_fromMetadata": {"_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": []},
			"_toMetadata": {"_ownerUsers": [], "_ownerGroups": [], "_visibility": "private", "_viewerUsers": [], "_validFromDateTime": "2020-01-01T00:00:00Z"},
		},
	)
}

# New: deny when referenced list is pending even if caller is direct owner
test_not_allow_member_when_from_list_pending_even_if_owner if {
	not allow with input as produce_input_replace(
		["tarcinapp.member"], true, {
			"_kind": "contains",
			"_listId": "list-pending",
			"_entityId": "entity-ok",
		},
		{
			"_kind": "contains",
			"_listId": "list-pending",
			"_entityId": "entity-ok",
			"_fromMetadata": {"_id": "list-pending", "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_visibility": "protected", "_validFromDateTime": null, "_validUntilDateTime": null},
			"_toMetadata": {"_id": "entity-ok", "_ownerUsers": [], "_ownerGroups": [], "_visibility": "public", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
		},
	)
}

# New: deny when target entity is pending even if caller is viewer user
test_not_allow_member_when_to_entity_pending_even_if_viewer_user if {
	not allow with input as produce_input_replace(
		["tarcinapp.member"], true, {
			"_kind": "contains",
			"_listId": "list-ok",
			"_entityId": "entity-pending",
		},
		{
			"_kind": "contains",
			"_listId": "list-ok",
			"_entityId": "entity-pending",
			"_fromMetadata": {"_id": "list-ok", "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_visibility": "public", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null},
			"_toMetadata": {"_id": "entity-pending", "_ownerUsers": [], "_ownerGroups": [], "_visibility": "private", "_viewerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_validFromDateTime": null, "_validUntilDateTime": null},
		},
	)
}

test_not_allow_member_change_listId if {
	not allow with input as produce_input_replace(
		["tarcinapp.member"], true, {
			"_kind": "contains",
			"_listId": "different-list-id",
			"_entityId": "entity-1",
		},
		{
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "entity-1",
			"_fromMetadata": {"_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": []},
			"_toMetadata": {"_ownerUsers": [], "_ownerGroups": [], "_visibility": "public", "_validFromDateTime": "2020-01-01T00:00:00Z"},
		},
	)
}

test_not_allow_member_change_entityId if {
	not allow with input as produce_input_replace(
		["tarcinapp.member"], true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "different-entity-id",
		},
		{
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "entity-1",
			"_fromMetadata": {"_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": []},
			"_toMetadata": {"_ownerUsers": [], "_ownerGroups": [], "_visibility": "public", "_validFromDateTime": "2020-01-01T00:00:00Z"},
		},
	)
}

test_not_allow_member_set_validUntil_without_field_role if {
	now := time.now_ns() / 1000000000
	validUntil := now - 1
	validUntilStr := time.format([validUntil * 1000000000, "UTC", "RFC3339"])

	not allow with input as produce_input_replace(
		["tarcinapp.member"], true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "entity-1",
			"_validUntilDateTime": validUntilStr,
		},
		{
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "entity-1",
			"_validUntilDateTime": null,
			"_fromMetadata": {"_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": []},
			"_toMetadata": {"_ownerUsers": [], "_ownerGroups": [], "_visibility": "public", "_validFromDateTime": "2020-01-01T00:00:00Z"},
		},
	)
}

test_not_allow_member_set_validUntil_wrong_range_with_field_role if {
	now := time.now_ns() / 1000000000
	validUntil := now - 400
	validUntilStr := time.format([validUntil * 1000000000, "UTC", "RFC3339"])

	not allow with input as produce_input_replace(
		[
			"tarcinapp.member",
			"tarcinapp.relations.fields._validUntilDateTime.update",
		],
		true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "entity-1",
			"_validUntilDateTime": validUntilStr,
		},
		{
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "entity-1",
			"_validUntilDateTime": null,
			"_fromMetadata": {"_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": []},
			"_toMetadata": {"_ownerUsers": [], "_ownerGroups": [], "_visibility": "public", "_validFromDateTime": "2020-01-01T00:00:00Z"},
		},
	)
}

# ==========================
# Visitor test cases
# ==========================

test_not_allow_visitor_even_with_field_roles if {
	not allow with input as produce_input_replace(
		[
			"tarcinapp.visitor",
			"tarcinapp.relations.fields._validUntilDateTime.update",
		],
		true, {
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "entity-1",
			"_validUntilDateTime": "2024-01-01T00:00:00Z",
		},
		{
			"_kind": "contains",
			"_listId": "7ef64686-976f-4737-aebd-e4aea445202d",
			"_entityId": "entity-1",
			"_fromMetadata": {"_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": []},
			"_toMetadata": {"_ownerUsers": [], "_ownerGroups": [], "_visibility": "public", "_validFromDateTime": "2020-01-01T00:00:00Z"},
		},
	)
}
