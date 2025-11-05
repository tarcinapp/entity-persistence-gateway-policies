package policies.auth.routes.entityReactions.createChildEntityReaction.policy

import data.policies.util.common.test as test

# Helper to construct input for creating a child reaction under a parent reaction
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
test_allow_admin_top_level_role if {
	allow with input as produce_reaction_input(
		["tarcinapp.admin"], true,
		{
			"_entityId": "entity-1",
			"_kind": "comment",
			"text": "child reaction content",
		},
		{
			"_id": "reaction-parent-1",
			"_kind": "comment",
			"_entityId": "entity-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
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

### Editor roles
test_allow_editor_granular_roles if {
	allow with input as produce_reaction_input(
		["tarcinapp.reactions.find.editor", "tarcinapp.reactions.create.editor", "tarcinapp.entities.find.editor"], true,
		{
			"_entityId": "entity-1",
			"_kind": "comment",
			"text": "child reaction content",
		},
		{
			"_id": "reaction-parent-1",
			"_kind": "comment",
			"_entityId": "entity-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
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

### Member roles
test_allow_top_level_member_roles if {
	allow with input as produce_reaction_input(
		["tarcinapp.member"], true,
		{
			"_entityId": "entity-1",
			"_kind": "comment",
			"text": "child reaction content",
		},
		{
			"_id": "reaction-parent-1",
			"_kind": "comment",
			"_entityId": "entity-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
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

test_allow_member_create_child_reaction_parent_private_active_viewer_user_entity_public_active if {
	allow with input as produce_reaction_input(
		["tarcinapp.entities.find.member", "tarcinapp.reactions.create.member", "tarcinapp.reactions.find.member"], true,
		{
			"_entityId": "entity-1",
			"_kind": "comment",
			"text": "child reaction content",
		},
		{
			"_id": "reaction-parent-1",
			"_kind": "comment",
			"_entityId": "entity-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
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

# Member state/visibility positives
test_allow_member_group_owned_protected_active if {
	allow with input as produce_reaction_input(
		["tarcinapp.entities.find.member", "tarcinapp.reactions.find.member", "tarcinapp.reactions.create.member"], true,
		{"_entityId": "entity-1", "_kind": "comment", "text": "child reaction content"},
		{
			"_id": "reaction-parent-1",
			"_kind": "comment",
			"_entityId": "entity-1",
			"_ownerUsers": [],
			"_ownerGroups": ["group-1"],
			"_visibility": "protected",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": [],
			"_viewerGroups": [],
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

test_allow_member_parent_viewer_groups_protected_active if {
	allow with input as produce_reaction_input(
		["tarcinapp.entities.find.member", "tarcinapp.reactions.find.member", "tarcinapp.reactions.create.member"], true,
		{"_entityId": "entity-1", "_kind": "comment", "text": "child reaction content"},
		{
			"_id": "reaction-parent-1",
			"_kind": "comment",
			"_entityId": "entity-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "protected",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": [],
			"_viewerGroups": ["group-1"],
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

### Granular role combinations
test_allow_records_and_reactions_member_roles if {
	allow with input as produce_reaction_input(
		["tarcinapp.records.member", "tarcinapp.reactions.member"], true,
		{
			"_entityId": "entity-1",
			"_kind": "comment",
			"text": "child reaction content",
		},
		{
			"_id": "reaction-parent-1",
			"_kind": "comment",
			"_entityId": "entity-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
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

test_allow_explicit_find_and_create_roles if {
	allow with input as produce_reaction_input(
		["tarcinapp.records.find.member", "tarcinapp.reactions.find.member", "tarcinapp.reactions.create.member"], true,
		{
			"_entityId": "entity-1",
			"_kind": "comment",
			"text": "child reaction content",
		},
		{
			"_id": "reaction-parent-1",
			"_kind": "comment",
			"_entityId": "entity-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
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

test_allow_entities_and_entityReactions_member_roles if {
	allow with input as produce_reaction_input(
		["tarcinapp.entities.member", "tarcinapp.entityReactions.member"], true,
		{
			"_entityId": "entity-1",
			"_kind": "comment",
			"text": "child reaction content",
		},
		{
			"_id": "reaction-parent-1",
			"_kind": "comment",
			"_entityId": "entity-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
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

test_allow_entities_find_and_reactions_member_roles if {
	allow with input as produce_reaction_input(
		["tarcinapp.entities.find.member", "tarcinapp.reactions.member"], true,
		{
			"_entityId": "entity-1",
			"_kind": "comment",
			"text": "child reaction content",
		},
		{
			"_id": "reaction-parent-1",
			"_kind": "comment",
			"_entityId": "entity-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
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

## ==========================
## NEGATIVE TESTS
## ==========================

### Admin roles
test_not_allow_admin_unverified_email if {
	not allow with input as produce_reaction_input(
		["tarcinapp.admin"], false,
		{
			"_entityId": "entity-1",
			"_kind": "comment",
			"text": "child reaction content",
		},
		{
			"_id": "reaction-parent-1",
			"_kind": "comment",
			"_entityId": "entity-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
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

### Editor roles
test_not_allow_editor_missing_entities_find if {
	not allow with input as produce_reaction_input(
		["tarcinapp.reactions.find.editor", "tarcinapp.reactions.create.editor"], true,
		{
			"_entityId": "entity-1",
			"_kind": "comment",
			"text": "child reaction content",
		},
		{
			"_id": "reaction-parent-1",
			"_kind": "comment",
			"_entityId": "entity-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
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

### Member roles
test_not_allow_member_missing_reactions_find_role if {
	not allow with input as produce_reaction_input(
		["tarcinapp.entities.find.member", "tarcinapp.reactions.create.member"], true,
		{
			"_entityId": "entity-1",
			"_kind": "comment",
			"text": "child reaction content",
		},
		{
			"_id": "reaction-parent-1",
			"_kind": "comment",
			"_entityId": "entity-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
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

# Missing entities.find.* prevents seeing the related entity for members
test_not_allow_member_missing_entities_find_role if {
	not allow with input as produce_reaction_input(
		["tarcinapp.reactions.find.member", "tarcinapp.reactions.create.member"], true,
		{"_entityId": "entity-1", "_kind": "comment", "text": "child reaction content"},
		{
			"_id": "reaction-parent-1",
			"_kind": "comment",
			"_entityId": "entity-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
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

# Parent/Entity state negatives for members
test_not_allow_member_parent_pending if {
	not allow with input as produce_reaction_input(
		["tarcinapp.entities.find.member", "tarcinapp.reactions.find.member", "tarcinapp.reactions.create.member"], true,
		{"_entityId": "entity-1", "_kind": "comment", "text": "child reaction content"},
		{
			"_id": "reaction-parent-1",
			"_kind": "comment",
			"_entityId": "entity-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2999-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
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

test_not_allow_member_parent_expired if {
	not allow with input as produce_reaction_input(
		["tarcinapp.entities.find.member", "tarcinapp.reactions.find.member", "tarcinapp.reactions.create.member"], true,
		{"_entityId": "entity-1", "_kind": "comment", "text": "child reaction content"},
		{
			"_id": "reaction-parent-1",
			"_kind": "comment",
			"_entityId": "entity-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": "2021-01-01T00:00:00Z",
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
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

test_not_allow_member_parent_viewer_groups_private if {
	not allow with input as produce_reaction_input(
		["tarcinapp.entities.find.member", "tarcinapp.reactions.find.member", "tarcinapp.reactions.create.member"], true,
		{"_entityId": "entity-1", "_kind": "comment", "text": "child reaction content"},
		{
			"_id": "reaction-parent-1",
			"_kind": "comment",
			"_entityId": "entity-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": [],
			"_viewerGroups": ["group-1"],
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

test_not_allow_member_entity_pending if {
	not allow with input as produce_reaction_input(
		["tarcinapp.entities.find.member", "tarcinapp.reactions.find.member", "tarcinapp.reactions.create.member"], true,
		{"_entityId": "entity-1", "_kind": "comment", "text": "child reaction content"},
		{
			"_id": "reaction-parent-1",
			"_kind": "comment",
			"_entityId": "entity-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
			"_relationMetadata": {
				"_id": "entity-1",
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

test_not_allow_member_entity_expired if {
	not allow with input as produce_reaction_input(
		["tarcinapp.entities.find.member", "tarcinapp.reactions.find.member", "tarcinapp.reactions.create.member"], true,
		{"_entityId": "entity-1", "_kind": "comment", "text": "child reaction content"},
		{
			"_id": "reaction-parent-1",
			"_kind": "comment",
			"_entityId": "entity-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
			"_relationMetadata": {
				"_id": "entity-1",
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

test_not_allow_member_entity_private_not_viewable if {
	not allow with input as produce_reaction_input(
		["tarcinapp.entities.find.member", "tarcinapp.reactions.find.member", "tarcinapp.reactions.create.member"], true,
		{"_entityId": "entity-1", "_kind": "comment", "text": "child reaction content"},
		{
			"_id": "reaction-parent-1",
			"_kind": "comment",
			"_entityId": "entity-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
			"_relationMetadata": {
				"_id": "entity-1",
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
# Missing reactions.create.* denies creation even if find roles are present
test_not_allow_member_missing_reactions_create_role if {
	not allow with input as produce_reaction_input(
		["tarcinapp.entities.find.member", "tarcinapp.reactions.find.member"], true,
		{"_entityId": "entity-1", "_kind": "comment", "text": "child reaction content"},
		{
			"_id": "reaction-parent-1",
			"_kind": "comment",
			"_entityId": "entity-1",
			"_ownerUsers": [],
			"_ownerGroups": [],
			"_visibility": "private",
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null,
			"_viewerUsers": ["user-1"],
			"_viewerGroups": [],
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
