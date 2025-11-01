package policies.auth.routes.entityReactions.replaceEntityReactionById.policy

import data.policies.util.common.test as test

# Member can replace a reaction if:
# - Entity is active and public (visible to member)
# - Caller has tarcinapp.entities.find.member and tarcinapp.reactions.manage.member roles
# - Reaction is protected
# - One of the user's groups is in _ownerGroups of the reaction (ownership via group)
# - Reaction is pending (_validFromDateTime and _validUntilDateTime are null)
test_allow_member_replace_protected_group_owned_pending_reaction if {
	allow with input as {
		"appShortcode": "tarcinapp",
		"requestPayload": {
			"_id": "reaction-1",
			"_entityId": "entity-1",
			"_ownerUsers": [],
			"_ownerGroups": ["group-1", "group-2"],
			"_visibility": "protected",
			"_validFromDateTime": null,
			"_validUntilDateTime": null,
			"text": "Updated reaction content",
		},
		"originalRecord": {
			"_id": "reaction-1",
			"_entityId": "entity-1",
			"_ownerUsers": [],
			"_ownerGroups": ["group-1", "group-2"],
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
		"encodedJwt": test.produce_token({
			"sub": "user-1",
			"groups": ["group-1"],
			"roles": [
				"tarcinapp.entities.find.member",
				"tarcinapp.reactions.update.member",
			],
			"email_verified": true,
		}),
	}
}
