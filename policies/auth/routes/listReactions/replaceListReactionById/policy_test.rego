package policies.auth.routes.listReactions.replaceListReactionById.policy

import data.policies.util.common.test as test

# Helper function to produce test input for reaction replacement
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

# --- Admin role tests ---

# Admin can replace a reaction regardless of list visibility or ownership
test_allow_admin_replace_reaction_list_private if {
	allow with input as produce_reaction_input(
		["tarcinapp.admin"], true,
		{
			"_id": "reaction-1",
			"_listId": "list-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Updated reaction content",
		},
		{
			"_id": "reaction-1",
			"_listId": "list-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Original reaction content",
			"_relationMetadata": {
				"_id": "list-1",
				"_ownerUsers": ["other-user"],
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

# Admin can replace reaction even if list is inactive
test_allow_admin_replace_reaction_list_inactive if {
	allow with input as produce_reaction_input(
		["tarcinapp.admin"], true,
		{
			"_id": "reaction-1",
			"_listId": "list-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Updated reaction content",
		},
		{
			"_id": "reaction-1",
			"_listId": "list-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Original reaction content",
			"_relationMetadata": {
				"_id": "list-1",
				"_ownerUsers": ["user-1"],
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

# Admin can replace reaction owned by other user
test_allow_admin_replace_other_user_reaction if {
	allow with input as produce_reaction_input(
		["tarcinapp.admin"], true,
		{
			"_id": "reaction-1",
			"_listId": "list-1",
			"_ownerUsers": ["other-user"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Updated reaction content",
		},
		{
			"_id": "reaction-1",
			"_listId": "list-1",
			"_ownerUsers": ["other-user"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Original reaction content",
			"_relationMetadata": {
				"_id": "list-1",
				"_ownerUsers": ["other-user"],
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

# --- Editor role tests ---

# Editor can replace reaction on any list with same forbidden fields
test_allow_editor_replace_reaction_any_list if {
	allow with input as produce_reaction_input(
		["tarcinapp.editor"], true,
		{
			"_id": "reaction-1",
			"_listId": "list-1",
			"_ownerUsers": ["other-user"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"_createdDateTime": "2022-01-01T00:00:00Z",
			"_lastUpdatedDateTime": "2022-01-01T00:00:00Z",
			"_lastUpdatedBy": "original-user",
			"_createdBy": "original-user",
			"text": "Updated reaction content",
		},
		{
			"_id": "reaction-1",
			"_listId": "list-1",
			"_ownerUsers": ["other-user"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"_createdDateTime": "2022-01-01T00:00:00Z",
			"_lastUpdatedDateTime": "2022-01-01T00:00:00Z",
			"_lastUpdatedBy": "original-user",
			"_createdBy": "original-user",
			"text": "Original reaction content",
			"_relationMetadata": {
				"_id": "list-1",
				"_ownerUsers": [],
				"_ownerGroups": ["other-group"],
				"_visibility": "protected",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
		},
	)
}

# --- Member role tests ---

# Member can replace a reaction if:
# - List is active and public (visible to member)
# - Caller has tarcinapp.lists.find.member and tarcinapp.reactions.update.member roles
# - Reaction is protected
# - One of the user's groups is in _ownerGroups of the reaction (ownership via group)
# - Reaction is pending (_validFromDateTime and _validUntilDateTime are null)
test_allow_member_replace_protected_group_owned_pending_reaction if {
	allow with input as produce_reaction_input(
		["tarcinapp.lists.find.member", "tarcinapp.reactions.update.member"], true,
		{
			"_id": "reaction-1",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": ["group-1", "group-2"],
			"_visibility": "protected",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Updated reaction content",
		},
		{
			"_id": "reaction-1",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": ["group-1", "group-2"],
			"_visibility": "protected",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Original reaction content",
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

# Member can replace user-owned pending reaction on public list
test_allow_member_replace_user_owned_reaction_with_records_roles if {
	allow with input as produce_reaction_input(
		["tarcinapp.records.member", "tarcinapp.listReactions.member"], true,
		{
			"_id": "reaction-1",
			"_listId": "list-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Updated reaction content",
		},
		{
			"_id": "reaction-1",
			"_listId": "list-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Original reaction content",
			"_relationMetadata": {
				"_id": "list-1",
				"_ownerUsers": ["other-user"],
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

# Member cannot replace reaction when list is private (not visible)
test_not_allow_member_replace_reaction_list_private_with_lists_member if {
	not allow with input as produce_reaction_input(
		["tarcinapp.lists.find.member", "tarcinapp.reactions.update.member"], true,
		{
			"_id": "reaction-1",
			"_listId": "list-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Updated reaction content",
		},
		{
			"_id": "reaction-1",
			"_listId": "list-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Original reaction content",
			"_relationMetadata": {
				"_id": "list-1",
				"_ownerUsers": ["other-user"],
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

# Member cannot replace reaction when list is inactive (past validUntilDateTime)
test_not_allow_member_replace_reaction_list_inactive_with_records_roles if {
	not allow with input as produce_reaction_input(
		["tarcinapp.lists.find.member", "tarcinapp.reactions.update.member"], true,
		{
			"_id": "reaction-1",
			"_listId": "list-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Updated reaction content",
		},
		{
			"_id": "reaction-1",
			"_listId": "list-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Original reaction content",
			"_relationMetadata": {
				"_id": "list-1",
				"_ownerUsers": ["user-1"],
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

# Member cannot replace reaction when list hasn't become active yet (validFromDateTime in future)

# Member cannot replace reaction when not owning it
test_not_allow_member_replace_other_user_reaction_with_tarcinapp_member if {
	not allow with input as produce_reaction_input(
		["tarcinapp.member"], true,
		{
			"_id": "reaction-1",
			"_listId": "list-1",
			"_ownerUsers": ["other-user"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Updated reaction content",
		},
		{
			"_id": "reaction-1",
			"_listId": "list-1",
			"_ownerUsers": ["other-user"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Original reaction content",
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

# Member cannot replace inactive reaction (past validUntilDateTime)
test_not_allow_member_replace_inactive_reaction_with_reactions_roles if {
	not allow with input as produce_reaction_input(
		["tarcinapp.lists.find.member", "tarcinapp.reactions.update.member"], true,
		{
			"_id": "reaction-1",
			"_listId": "list-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": "2021-01-01T00:00:00Z",
			"text": "Updated reaction content",
		},
		{
			"_id": "reaction-1",
			"_listId": "list-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": "2021-01-01T00:00:00Z",
			"text": "Original reaction content",
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

# Member can see list through viewer group even if not owner
test_allow_member_replace_reaction_list_viewer_group if {
	allow with input as produce_reaction_input(
		["tarcinapp.lists.find.editor", "tarcinapp.reactions.member"], true,
		{
			"_id": "reaction-1",
			"_listId": "list-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": [],
			"_visibility": "protected",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Updated reaction content",
		},
		{
			"_id": "reaction-1",
			"_listId": "list-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": [],
			"_visibility": "protected",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Original reaction content",
			"_relationMetadata": {
				"_id": "list-1",
				"_ownerUsers": ["other-user"],
				"_ownerGroups": ["other-group"],
				"_visibility": "protected",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_viewerUsers": [],
				"_viewerGroups": ["group-1"],
			},
		},
	)
}

# Member can see list through viewer user (direct access)
test_allow_member_replace_reaction_list_viewer_user if {
	allow with input as produce_reaction_input(
		["tarcinapp.lists.find.member", "tarcinapp.reactions.update.member"], true,
		{
			"_id": "reaction-1",
			"_listId": "list-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": [],
			"_visibility": "protected",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Updated reaction content",
		},
		{
			"_id": "reaction-1",
			"_listId": "list-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": [],
			"_visibility": "protected",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Original reaction content",
			"_relationMetadata": {
				"_id": "list-1",
				"_ownerUsers": ["other-user"],
				"_ownerGroups": ["other-group"],
				"_visibility": "protected",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_viewerUsers": ["user-1"],
				"_viewerGroups": [],
			},
		},
	)
}

# Member owns list through group and can replace reaction
test_allow_member_replace_reaction_list_group_owned if {
	allow with input as produce_reaction_input(
		["tarcinapp.lists.find.member", "tarcinapp.reactions.update.member"], true,
		{
			"_id": "reaction-1",
			"_listId": "list-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Updated reaction content",
		},
		{
			"_id": "reaction-1",
			"_listId": "list-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Original reaction content",
			"_relationMetadata": {
				"_id": "list-1",
				"_ownerUsers": ["other-user"],
				"_ownerGroups": ["group-1"],
				"_visibility": "protected",
				"_validFromDateTime": "2020-01-01T00:00:00Z",
				"_validUntilDateTime": null,
				"_viewerUsers": [],
				"_viewerGroups": [],
			},
		},
	)
}

# Member cannot modify reaction ownership to a group they don't belong to
test_not_allow_member_add_ownerGroup_they_do_not_belong_to if {
	not allow with input as produce_reaction_input(
		["tarcinapp.lists.find.member", "tarcinapp.reactions.update.member"], true,
		{
			"_id": "reaction-1",
			"_listId": "list-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": ["other-group"],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Updated reaction content",
		},
		{
			"_id": "reaction-1",
			"_listId": "list-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Original reaction content",
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

# Member can add a group they belong to as owner
test_allow_member_add_ownerGroup_they_belong_to if {
	allow with input as produce_reaction_input(
		["tarcinapp.lists.find.member", "tarcinapp.reactions.update.member"], true,
		{
			"_id": "reaction-1",
			"_listId": "list-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": ["group-2"],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Updated reaction content",
		},
		{
			"_id": "reaction-1",
			"_listId": "list-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Original reaction content",
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

# Member cannot remove a group from reaction ownership (group-owned)
test_not_allow_member_remove_ownerGroup_they_belong_to if {
	not allow with input as produce_reaction_input(
		["tarcinapp.lists.find.member", "tarcinapp.reactions.update.member"], true,
		{
			"_id": "reaction-1",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Updated reaction content",
		},
		{
			"_id": "reaction-1",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": ["group-1"],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Original reaction content",
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

# Member cannot change reaction to private if owned by group
test_not_allow_member_change_visibility_to_private_for_group_owned if {
	not allow with input as produce_reaction_input(
		["tarcinapp.lists.find.member", "tarcinapp.reactions.update.member"], true,
		{
			"_id": "reaction-1",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": ["group-1"],
			"_visibility": "private",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Updated reaction content",
		},
		{
			"_id": "reaction-1",
			"_listId": "list-1",
			"_ownerUsers": [],
			"_ownerGroups": ["group-1"],
			"_visibility": "protected",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Original reaction content",
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

# Member cannot set validUntilDateTime on reaction without special role
test_not_allow_member_set_validUntilDateTime_without_field_role if {
	not allow with input as produce_reaction_input(
		["tarcinapp.lists.find.member", "tarcinapp.reactions.update.member"], true,
		{
			"_id": "reaction-1",
			"_listId": "list-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": "2024-06-01T00:00:00Z",
			"text": "Updated reaction content",
		},
		{
			"_id": "reaction-1",
			"_listId": "list-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Original reaction content",
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

# Member cannot verify email and replace reaction
test_not_allow_member_replace_reaction_unverified_email if {
	not allow with input as produce_reaction_input(
		["tarcinapp.lists.find.member", "tarcinapp.reactions.update.member"], false,
		{
			"_id": "reaction-1",
			"_listId": "list-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Updated reaction content",
		},
		{
			"_id": "reaction-1",
			"_listId": "list-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Original reaction content",
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
