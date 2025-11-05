package policies.auth.routes.listReactions.findParentsByListReactionId.policy

import data.policies.util.common.test as test

# Helper to construct input for finding parent list reactions of a child reaction
produce_input(roles, is_email_verified, originalRecord) := test_body if {
	test_body = {
		"appShortcode": "tarcinapp",
		"originalRecord": originalRecord,
		"encodedJwt": test.produce_token({
			"sub": "user-1",
			"groups": ["group-1", "group-2"],
			"roles": roles,
			"email_verified": is_email_verified,
		}),
	}
}

## ==========================
## POSITIVE TESTS
## ==========================

### Admin roles
test_allow_admin_top_level_role if {
	allow with input as produce_input(
		["tarcinapp.admin"], true,
		{
			"_id": "list-reaction-child-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
		},
	)
}

test_allow_admin_child_private_viewer_user if {
	allow with input as produce_input(
		["tarcinapp.reactions.find.admin"], true,
		{
			"_id": "list-reaction-child-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
		},
	)
}

### Editor roles
test_allow_editor_granular_roles if {
	allow with input as produce_input(
		["tarcinapp.reactions.find.editor"], true,
		{
			"_id": "list-reaction-child-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
		},
	)
}

### Member roles
test_allow_member_top_level_role if {
	allow with input as produce_input(
		["tarcinapp.member"], true,
		{
			"_id": "list-reaction-child-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
		},
	)
}

test_allow_member_child_private_active_viewer_user if {
	allow with input as produce_input(
		["tarcinapp.listReactions.find.member"], true,
		{
			"_id": "list-reaction-child-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
		},
	)
}

test_allow_member_child_group_owned_protected_active if {
	allow with input as produce_input(
		["tarcinapp.reactions.find.member"], true,
		{
			"_id": "list-reaction-child-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": ["group-1"],
			"_visibility": "protected",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": [],
			"_viewerGroups": [],
		},
	)
}

test_allow_member_child_viewer_groups_protected_active if {
	allow with input as produce_input(
		["tarcinapp.reactions.find.member"], true,
		{
			"_id": "list-reaction-child-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "protected",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": [],
			"_viewerGroups": ["group-1"],
		},
	)
}

test_allow_member_child_public_active if {
	allow with input as produce_input(
		["tarcinapp.reactions.find.member"], true,
		{
			"_id": "list-reaction-child-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": [],
			"_viewerGroups": [],
		},
	)
}

### Visitor roles
test_allow_visitor_child_public_active if {
	allow with input as produce_input(
		["tarcinapp.reactions.find.visitor"], true,
		{
			"_id": "list-reaction-child-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": [],
			"_viewerGroups": [],
		},
	)
}

### Granular role combinations
test_allow_records_and_reactions_member_roles if {
	allow with input as produce_input(
		["tarcinapp.records.member", "tarcinapp.reactions.member"], true,
		{
			"_id": "list-reaction-child-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
		},
	)
}

test_allow_explicit_find_roles if {
	allow with input as produce_input(
		["tarcinapp.reactions.find.member"], true,
		{
			"_id": "list-reaction-child-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
		},
	)
}

## ==========================
## NEGATIVE TESTS
## ==========================

### Admin roles
test_not_allow_admin_unverified_email if {
	not allow with input as produce_input(
		["tarcinapp.admin"], false,
		{
			"_id": "list-reaction-child-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
		},
	)
}

test_not_allow_admin_child_private_not_viewable if {
	not allow with input as produce_input(
		["tarcinapp.admin"], true,
		{
			"_id": "list-reaction-child-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": [],
			"_viewerGroups": [],
		},
	)
}

### Editor roles
test_not_allow_editor_unverified_email if {
	not allow with input as produce_input(
		["tarcinapp.reactions.find.editor"], false,
		{
			"_id": "list-reaction-child-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
		},
	)
}

test_not_allow_editor_child_private_not_viewable if {
	not allow with input as produce_input(
		["tarcinapp.reactions.find.editor"], true,
		{
			"_id": "list-reaction-child-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": [],
			"_viewerGroups": [],
		},
	)
}

### Member roles
test_not_allow_member_missing_find_role if {
	not allow with input as produce_input(
		["tarcinapp.reactions.create.member"], true,
		{
			"_id": "list-reaction-child-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
		},
	)
}

test_not_allow_member_child_expired if {
	not allow with input as produce_input(
		["tarcinapp.reactions.find.member"], true,
		{
			"_id": "list-reaction-child-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": "2021-01-01T00:00:00Z",
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
		},
	)
}

test_not_allow_member_child_viewer_groups_private if {
	not allow with input as produce_input(
		["tarcinapp.reactions.find.member"], true,
		{
			"_id": "list-reaction-child-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": [],
			"_viewerGroups": ["group-1"],
		},
	)
}

test_not_allow_member_child_private_not_viewable if {
	not allow with input as produce_input(
		["tarcinapp.reactions.find.member"], true,
		{
			"_id": "list-reaction-child-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": [],
			"_viewerGroups": [],
		},
	)
}

### Visitor roles
test_not_allow_visitor_child_private if {
	not allow with input as produce_input(
		["tarcinapp.reactions.find.visitor"], true,
		{
			"_id": "list-reaction-child-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
		},
	)
}

test_not_allow_visitor_child_expired if {
	not allow with input as produce_input(
		["tarcinapp.reactions.find.visitor"], true,
		{
			"_id": "list-reaction-child-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": "2021-01-01T00:00:00Z",
			"_viewerUsers": [],
			"_viewerGroups": [],
		},
	)
}

### Granular role combinations
test_not_allow_member_missing_reactions_find_role if {
	not allow with input as produce_input(
		["tarcinapp.lists.find.member"], true,
		{
			"_id": "list-reaction-child-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
		},
	)
}
