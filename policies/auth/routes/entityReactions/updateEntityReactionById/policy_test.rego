package policies.auth.routes.entityReactions.updateEntityReactionById.policy

import data.policies.util.common.test as test

# Helper function to produce test input for reaction update
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

# Admin can update reaction with minimal payload (partial update)
test_allow_admin_update_reaction_minimal_payload if {
	allow with input as produce_reaction_input(
		["tarcinapp.admin"], true,
		{"text": "Updated reaction content"},
		{
			"_id": "reaction-1",
			"_entityId": "entity-1",
			"_ownerUsers": ["other-user"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Original reaction content",
			"_relationMetadata": {
				"_id": "entity-1",
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

# Admin can update reaction on private entity
test_allow_admin_update_reaction_entity_private if {
	allow with input as produce_reaction_input(
		["tarcinapp.admin"], true,
		{
			"text": "Updated reaction content",
			"_visibility": "protected",
		},
		{
			"_id": "reaction-1",
			"_entityId": "entity-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Original reaction content",
			"_relationMetadata": {
				"_id": "entity-1",
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

# Admin can update reaction even if entity is inactive
test_allow_admin_update_reaction_entity_inactive if {
	allow with input as produce_reaction_input(
		["tarcinapp.admin"], true,
		{"text": "Updated reaction content"},
		{
			"_id": "reaction-1",
			"_entityId": "entity-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Original reaction content",
			"_relationMetadata": {
				"_id": "entity-1",
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

# Admin denied without email verification
test_not_allow_admin_update_reaction_unverified_email if {
	not allow with input as produce_reaction_input(
		["tarcinapp.admin"], false,
		{"text": "Updated reaction content"},
		{
			"_id": "reaction-1",
			"_entityId": "entity-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Original reaction content",
			"_relationMetadata": {
				"_id": "entity-1",
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

# --- Editor role tests ---

# Editor can update reaction with partial payload
test_allow_editor_update_reaction_minimal_payload if {
	allow with input as produce_reaction_input(
		["tarcinapp.editor"], true,
		{"text": "Updated reaction content"},
		{
			"_id": "reaction-1",
			"_entityId": "entity-1",
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
				"_id": "entity-1",
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

# Editor can update with metadata fields intact
test_allow_editor_update_reaction_with_metadata if {
	allow with input as produce_reaction_input(
		["tarcinapp.editor"], true,
		{
			"text": "Updated reaction content",
			"_createdDateTime": "2022-01-01T00:00:00Z",
			"_lastUpdatedDateTime": "2022-01-01T00:00:00Z",
			"_lastUpdatedBy": "original-user",
			"_createdBy": "original-user",
		},
		{
			"_id": "reaction-1",
			"_entityId": "entity-1",
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
				"_id": "entity-1",
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

# Member can update user-owned reaction without ownership fields in payload
test_allow_member_update_user_owned_reaction_no_ownership_in_payload if {
	allow with input as produce_reaction_input(
		["tarcinapp.member"], true,
		{"text": "Updated reaction content"},
		{
			"_id": "reaction-1",
			"_entityId": "entity-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Original reaction content",
			"_relationMetadata": {
				"_id": "entity-1",
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

# Member can update group-owned protected reaction
test_allow_member_update_group_owned_protected_reaction if {
	allow with input as produce_reaction_input(
		["tarcinapp.entities.find.member", "tarcinapp.reactions.member"], true,
		{"text": "Updated reaction content"},
		{
			"_id": "reaction-1",
			"_entityId": "entity-1",
			"_ownerUsers": [],
			"_ownerGroups": ["group-1"],
			"_visibility": "protected",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Original reaction content",
			"_relationMetadata": {
				"_id": "entity-1",
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

# Member can update reaction with ownerUsers in payload if it contains user ID
test_allow_member_update_with_ownerUsers_containing_user if {
	allow with input as produce_reaction_input(
		["tarcinapp.records.member", "tarcinapp.entityReactions.member"], true,
		{
			"text": "Updated reaction content",
			"_ownerUsers": ["user-1"],
		},
		{
			"_id": "reaction-1",
			"_entityId": "entity-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Original reaction content",
			"_relationMetadata": {
				"_id": "entity-1",
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

# Member cannot update expired reaction (both update and replace deny expired)
test_not_allow_member_update_expired_reaction if {
	not allow with input as produce_reaction_input(
		["tarcinapp.entities.find.member", "tarcinapp.reactions.update.member"], true,
		{"text": "Updated reaction content"},
		{
			"_id": "reaction-1",
			"_entityId": "entity-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": "2021-01-01T00:00:00Z",
			"text": "Original reaction content",
			"_relationMetadata": {
				"_id": "entity-1",
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

# Member can see entity through viewer group even if not owner
test_allow_member_update_reaction_entity_viewer_group if {
	allow with input as produce_reaction_input(
		["tarcinapp.entities.find.editor", "tarcinapp.reactions.member"], true,
		{"text": "Updated reaction content"},
		{
			"_id": "reaction-1",
			"_entityId": "entity-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": [],
			"_visibility": "protected",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Original reaction content",
			"_relationMetadata": {
				"_id": "entity-1",
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

# Member can see entity through viewer user (direct access)
test_allow_member_update_reaction_entity_viewer_user if {
	allow with input as produce_reaction_input(
		["tarcinapp.entities.find.member", "tarcinapp.reactions.update.member"], true,
		{"text": "Updated reaction content"},
		{
			"_id": "reaction-1",
			"_entityId": "entity-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": [],
			"_visibility": "protected",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Original reaction content",
			"_relationMetadata": {
				"_id": "entity-1",
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

# Member can add a group they belong to
test_allow_member_add_ownerGroup_they_belong_to if {
	allow with input as produce_reaction_input(
		["tarcinapp.entities.find.member", "tarcinapp.reactions.update.member"], true,
		{
			"text": "Updated reaction content",
			"_ownerGroups": ["group-2"],
		},
		{
			"_id": "reaction-1",
			"_entityId": "entity-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Original reaction content",
			"_relationMetadata": {
				"_id": "entity-1",
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

# Member cannot update reaction when entity is private (not visible)
test_not_allow_member_update_reaction_entity_private if {
	not allow with input as produce_reaction_input(
		["tarcinapp.entities.find.member", "tarcinapp.reactions.update.member"], true,
		{"text": "Updated reaction content"},
		{
			"_id": "reaction-1",
			"_entityId": "entity-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Original reaction content",
			"_relationMetadata": {
				"_id": "entity-1",
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

# Member cannot update reaction when entity is inactive (past validUntilDateTime)
test_not_allow_member_update_reaction_entity_inactive if {
	not allow with input as produce_reaction_input(
		["tarcinapp.entities.find.member", "tarcinapp.reactions.update.member"], true,
		{"text": "Updated reaction content"},
		{
			"_id": "reaction-1",
			"_entityId": "entity-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Original reaction content",
			"_relationMetadata": {
				"_id": "entity-1",
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

# Member cannot update reaction when not owning it
test_not_allow_member_update_other_user_reaction if {
	not allow with input as produce_reaction_input(
		["tarcinapp.member"], true,
		{"text": "Updated reaction content"},
		{
			"_id": "reaction-1",
			"_entityId": "entity-1",
			"_ownerUsers": ["other-user"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Original reaction content",
			"_relationMetadata": {
				"_id": "entity-1",
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

# Member cannot add a group they don't belong to
test_not_allow_member_add_ownerGroup_they_do_not_belong_to if {
	not allow with input as produce_reaction_input(
		["tarcinapp.entities.find.member", "tarcinapp.reactions.update.member"], true,
		{
			"text": "Updated reaction content",
			"_ownerGroups": ["other-group"],
		},
		{
			"_id": "reaction-1",
			"_entityId": "entity-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Original reaction content",
			"_relationMetadata": {
				"_id": "entity-1",
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

# Member cannot remove groups from group-owned reaction
test_not_allow_member_remove_ownerGroup_from_group_owned if {
	not allow with input as produce_reaction_input(
		["tarcinapp.entities.find.member", "tarcinapp.reactions.update.member"], true,
		{
			"text": "Updated reaction content",
			"_ownerGroups": [],
		},
		{
			"_id": "reaction-1",
			"_entityId": "entity-1",
			"_ownerUsers": [],
			"_ownerGroups": ["group-1"],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Original reaction content",
			"_relationMetadata": {
				"_id": "entity-1",
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

# Member cannot change visibility to private for group-owned reaction
test_not_allow_member_change_visibility_to_private_for_group_owned if {
	not allow with input as produce_reaction_input(
		["tarcinapp.entities.find.member", "tarcinapp.reactions.update.member"], true,
		{
			"text": "Updated reaction content",
			"_visibility": "private",
		},
		{
			"_id": "reaction-1",
			"_entityId": "entity-1",
			"_ownerUsers": [],
			"_ownerGroups": ["group-1"],
			"_visibility": "protected",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Original reaction content",
			"_relationMetadata": {
				"_id": "entity-1",
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

# Member cannot update with ownerUsers not containing their ID (for user-owned)
test_not_allow_member_update_ownerUsers_without_user_id if {
	not allow with input as produce_reaction_input(
		["tarcinapp.entities.find.member", "tarcinapp.reactions.update.member"], true,
		{
			"text": "Updated reaction content",
			"_ownerUsers": ["other-user"],
		},
		{
			"_id": "reaction-1",
			"_entityId": "entity-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Original reaction content",
			"_relationMetadata": {
				"_id": "entity-1",
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

# Member denied with unverified email
test_not_allow_member_update_reaction_unverified_email if {
	not allow with input as produce_reaction_input(
		["tarcinapp.entities.find.member", "tarcinapp.reactions.update.member"], false,
		{"text": "Updated reaction content"},
		{
			"_id": "reaction-1",
			"_entityId": "entity-1",
			"_ownerUsers": ["user-1"],
			"_ownerGroups": [],
			"_visibility": "public",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Original reaction content",
			"_relationMetadata": {
				"_id": "entity-1",
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
