package policies.auth.routes.listReactions.createChildListReaction.policy

import data.policies.util.common.test as test

# Helper to construct input for creating a child list reaction under a parent reaction
produce_reaction_input(roles, is_email_verified, requestPayload, originalRecord) := test_body if {
	test_body = {
		"appShortcode": "tarcinapp",
		"requestPayload": requestPayload,
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
# Admin top-level role
test_allow_admin_top_level_role if {
	allow with input as produce_reaction_input(
		["tarcinapp.admin"], true,
		{
			"_listId": "list-1",
			"_kind": "comment",
			"text": "child reaction content",
		},
		{
			"_id": "list-reaction-parent-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
			"_relationMetadata": {
				"_id": "list-1",
				"_ownerUsers": [],
				"_ownerGroups": [],
				"_visibility": "public",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
		},
	)
}

### Editor roles
# Editor granular roles for reactions + list find editor
test_allow_editor_granular_roles if {
	allow with input as produce_reaction_input(
		["tarcinapp.reactions.find.editor", "tarcinapp.reactions.create.editor", "tarcinapp.lists.find.editor"], true,
		{
			"_listId": "list-1",
			"_kind": "comment",
			"text": "child reaction content",
		},
		{
			"_id": "list-reaction-parent-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
			"_relationMetadata": {
				"_id": "list-1",
				"_ownerUsers": [],
				"_ownerGroups": [],
				"_visibility": "public",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
		},
	)
}

### Member roles
# Top-level member role is sufficient for create/find from roles perspective
test_allow_top_level_member_roles if {
	allow with input as produce_reaction_input(
		["tarcinapp.member"], true,
		{
			"_listId": "list-1",
			"_kind": "comment",
			"text": "child reaction content",
		},
		{
			"_id": "list-reaction-parent-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
			"_relationMetadata": {
				"_id": "list-1",
				"_ownerUsers": [],
				"_ownerGroups": [],
				"_visibility": "public",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
		},
	)
}

# Single positive case mirroring entity-reaction test
# - Related list is public and active
# - Parent reaction is private and active, but caller is in viewerUsers
# - Caller has member roles for listReactions.create and lists.find and listReactions.find
# - Caller is email verified
# Expectation: allow == true

test_allow_member_create_child_reaction_parent_private_active_viewer_user_list_public_active if {
	allow with input as produce_reaction_input(
		["tarcinapp.lists.find.member", "tarcinapp.listReactions.create.member", "tarcinapp.listReactions.find.member"], true,
		{
			"_listId": "list-1",
			"_kind": "comment",
			"text": "child reaction content",
		},
		{
			"_id": "list-reaction-parent-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
			"_relationMetadata": {
				"_id": "list-1",
				"_ownerUsers": [],
				"_ownerGroups": [],
				"_visibility": "public",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
		},
	)
}

# Member state/visibility positives
# Group-owned parent, protected, active -> allowed
test_allow_member_group_owned_protected_active if {
	allow with input as produce_reaction_input(
		["tarcinapp.lists.find.member", "tarcinapp.listReactions.find.member", "tarcinapp.listReactions.create.member"], true,
		{"_listId": "list-1", "_kind": "comment", "text": "child reaction content"},
		{
			"_id": "list-reaction-parent-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": ["group-1"],
			"_visibility": "protected",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": [],
			"_viewerGroups": [],
			"_relationMetadata": {
				"_id": "list-1",
				"_ownerUsers": [],
				"_ownerGroups": [],
				"_visibility": "public",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
		},
	)
}

# ViewerGroups on parent, protected, active -> allowed
test_allow_member_parent_viewer_groups_protected_active if {
	allow with input as produce_reaction_input(
		["tarcinapp.lists.find.member", "tarcinapp.listReactions.find.member", "tarcinapp.listReactions.create.member"], true,
		{"_listId": "list-1", "_kind": "comment", "text": "child reaction content"},
		{
			"_id": "list-reaction-parent-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "protected",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": [],
			"_viewerGroups": ["group-1"],
			"_relationMetadata": {
				"_id": "list-1",
				"_ownerUsers": [],
				"_ownerGroups": [],
				"_visibility": "public",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
		},
	)
}

### Granular role combinations
# Records + Reactions member roles are sufficient
# (records scope is also accepted by lists/listReactions role utils)

test_allow_records_and_reactions_member_roles if {
	allow with input as produce_reaction_input(
		["tarcinapp.records.member", "tarcinapp.reactions.member"], true,
		{
			"_listId": "list-1",
			"_kind": "comment",
			"text": "child reaction content",
		},
		{
			"_id": "list-reaction-parent-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
			"_relationMetadata": {
				"_id": "list-1",
				"_ownerUsers": [],
				"_ownerGroups": [],
				"_visibility": "public",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
		},
	)
}

# Explicit find/create roles for records and listReactions

test_allow_explicit_find_and_create_roles if {
	allow with input as produce_reaction_input(
		["tarcinapp.records.find.member", "tarcinapp.listReactions.find.member", "tarcinapp.listReactions.create.member"], true,
		{
			"_listId": "list-1",
			"_kind": "comment",
			"text": "child reaction content",
		},
		{
			"_id": "list-reaction-parent-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
			"_relationMetadata": {
				"_id": "list-1",
				"_ownerUsers": [],
				"_ownerGroups": [],
				"_visibility": "public",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
		},
	)
}

# Lists + ListReactions member roles are sufficient

test_allow_lists_and_listReactions_member_roles if {
	allow with input as produce_reaction_input(
		["tarcinapp.lists.member", "tarcinapp.listReactions.member"], true,
		{
			"_listId": "list-1",
			"_kind": "comment",
			"text": "child reaction content",
		},
		{
			"_id": "list-reaction-parent-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
			"_relationMetadata": {
				"_id": "list-1",
				"_ownerUsers": [],
				"_ownerGroups": [],
				"_visibility": "public",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
		},
	)
}

# Lists.find + Reactions.member roles are sufficient

test_allow_lists_find_and_reactions_member_roles if {
	allow with input as produce_reaction_input(
		["tarcinapp.lists.find.member", "tarcinapp.reactions.member"], true,
		{
			"_listId": "list-1",
			"_kind": "comment",
			"text": "child reaction content",
		},
		{
			"_id": "list-reaction-parent-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
			"_relationMetadata": {
				"_id": "list-1",
				"_ownerUsers": [],
				"_ownerGroups": [],
				"_visibility": "public",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
		},
	)
}

## ==========================
## NEGATIVE TESTS
## ==========================

### Admin roles
# Admin must be email verified

test_not_allow_admin_unverified_email if {
	not allow with input as produce_reaction_input(
		["tarcinapp.admin"], false,
		{
			"_listId": "list-1",
			"_kind": "comment",
			"text": "child reaction content",
		},
		{
			"_id": "list-reaction-parent-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
			"_relationMetadata": {
				"_id": "list-1",
				"_ownerUsers": [],
				"_ownerGroups": [],
				"_visibility": "public",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
		},
	)
}

### Editor roles
# Editor missing lists.find.* cannot see related list

test_not_allow_editor_missing_lists_find if {
	not allow with input as produce_reaction_input(
		["tarcinapp.reactions.find.editor", "tarcinapp.reactions.create.editor"], true,
		{
			"_listId": "list-1",
			"_kind": "comment",
			"text": "child reaction content",
		},
		{
			"_id": "list-reaction-parent-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
			"_relationMetadata": {
				"_id": "list-1",
				"_ownerUsers": [],
				"_ownerGroups": [],
				"_visibility": "public",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
		},
	)
}

### Member roles
# Missing listReactions.find.* prevents seeing the parent reaction

test_not_allow_member_missing_reactions_find_role if {
	not allow with input as produce_reaction_input(
		["tarcinapp.lists.find.member", "tarcinapp.listReactions.create.member"], true,
		{
			"_listId": "list-1",
			"_kind": "comment",
			"text": "child reaction content",
		},
		{
			"_id": "list-reaction-parent-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
			"_relationMetadata": {
				"_id": "list-1",
				"_ownerUsers": [],
				"_ownerGroups": [],
				"_visibility": "public",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
		},
	)
}

# Missing lists.find.* prevents seeing the related list for members

test_not_allow_member_missing_lists_find_role if {
	not allow with input as produce_reaction_input(
		["tarcinapp.listReactions.find.member", "tarcinapp.listReactions.create.member"], true,
		{"_listId": "list-1", "_kind": "comment", "text": "child reaction content"},
		{
			"_id": "list-reaction-parent-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
			"_relationMetadata": {
				"_id": "list-1",
				"_ownerUsers": [],
				"_ownerGroups": [],
				"_visibility": "public",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
		},
	)
}

# Parent/Related list state negatives for members
# Parent reaction pending (validFrom in future) blocks member

test_not_allow_member_parent_pending if {
	not allow with input as produce_reaction_input(
		["tarcinapp.lists.find.member", "tarcinapp.listReactions.find.member", "tarcinapp.listReactions.create.member"], true,
		{"_listId": "list-1", "_kind": "comment", "text": "child reaction content"},
		{
			"_id": "list-reaction-parent-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2999-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
			"_relationMetadata": {
				"_id": "list-1",
				"_ownerUsers": [],
				"_ownerGroups": [],
				"_visibility": "public",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
		},
	)
}

# Parent reaction expired (validUntil in past) blocks member

test_not_allow_member_parent_expired if {
	not allow with input as produce_reaction_input(
		["tarcinapp.lists.find.member", "tarcinapp.listReactions.find.member", "tarcinapp.listReactions.create.member"], true,
		{"_listId": "list-1", "_kind": "comment", "text": "child reaction content"},
		{
			"_id": "list-reaction-parent-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": "2021-01-01T00:00:00Z",
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
			"_relationMetadata": {
				"_id": "list-1",
				"_ownerUsers": [],
				"_ownerGroups": [],
				"_visibility": "public",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
		},
	)
}

# Parent reaction viewerGroups present but private -> not allowed

test_not_allow_member_parent_viewer_groups_private if {
	not allow with input as produce_reaction_input(
		["tarcinapp.lists.find.member", "tarcinapp.listReactions.find.member", "tarcinapp.listReactions.create.member"], true,
		{"_listId": "list-1", "_kind": "comment", "text": "child reaction content"},
		{
			"_id": "list-reaction-parent-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": [],
			"_viewerGroups": ["group-1"],
			"_relationMetadata": {
				"_id": "list-1",
				"_ownerUsers": [],
				"_ownerGroups": [],
				"_visibility": "public",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
		},
	)
}

# Related list pending prevents member

test_not_allow_member_list_pending if {
	not allow with input as produce_reaction_input(
		["tarcinapp.lists.find.member", "tarcinapp.listReactions.find.member", "tarcinapp.listReactions.create.member"], true,
		{"_listId": "list-1", "_kind": "comment", "text": "child reaction content"},
		{
			"_id": "list-reaction-parent-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
			"_relationMetadata": {
				"_id": "list-1",
				"_ownerUsers": [],
				"_ownerGroups": [],
				"_visibility": "public",
				"_validFromDateTime": "2999-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
		},
	)
}

# Related list expired prevents member

test_not_allow_member_list_expired if {
	not allow with input as produce_reaction_input(
		["tarcinapp.lists.find.member", "tarcinapp.listReactions.find.member", "tarcinapp.listReactions.create.member"], true,
		{"_listId": "list-1", "_kind": "comment", "text": "child reaction content"},
		{
			"_id": "list-reaction-parent-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
			"_relationMetadata": {
				"_id": "list-1",
				"_ownerUsers": [],
				"_ownerGroups": [],
				"_visibility": "public",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": "2021-01-01T00:00:00Z",
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
		},
	)
}

# Related list private and not viewable prevents member

test_not_allow_member_list_private_not_viewable if {
	not allow with input as produce_reaction_input(
		["tarcinapp.lists.find.member", "tarcinapp.listReactions.find.member", "tarcinapp.listReactions.create.member"], true,
		{"_listId": "list-1", "_kind": "comment", "text": "child reaction content"},
		{
			"_id": "list-reaction-parent-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
			"_relationMetadata": {
				"_id": "list-1",
				"_ownerUsers": [],
				"_ownerGroups": [],
				"_visibility": "private",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
		},
	)
}

### Granular role combinations
# Missing listReactions.create.* denies creation even if find roles are present

test_not_allow_member_missing_reactions_create_role if {
	not allow with input as produce_reaction_input(
		["tarcinapp.lists.find.member", "tarcinapp.listReactions.find.member"], true,
		{"_listId": "list-1", "_kind": "comment", "text": "child reaction content"},
		{
			"_id": "list-reaction-parent-1",
			"_kind": "comment",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
			"_relationMetadata": {
				"_id": "list-1",
				"_ownerUsers": [],
				"_ownerGroups": [],
				"_visibility": "public",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
		},
	)
}
