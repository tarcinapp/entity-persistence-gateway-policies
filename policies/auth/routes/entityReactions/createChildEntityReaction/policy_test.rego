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

# Single positive test case as requested:
# - Related entity is public and active
# - Parent reaction is private and active, but caller is in viewerUsers
# - Caller has member roles for reactions.create and entities.find
# - Caller is email verified
# Expectation: allow == true

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
