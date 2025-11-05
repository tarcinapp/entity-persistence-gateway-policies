package policies.auth.routes.reactionsThroughEntity.deleteReactionsByEntityId.policy

import data.policies.util.common.test as test

produce_input_doc_by_role(role, is_email_verified) := test_body if {
	test_body = {
		"appShortcode": "tarcinapp",
		"httpMethod": "DELETE",
		"requestPath": "/entities/some-entity-id/reactions",
		"queryParams": {},
		"encodedJwt": test.produce_token({
			"sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
			"name": "John Doe",
			"admin": true,
			"iat": 1516239022,
			"email_verified": is_email_verified,
			"groups": ["my-group"],
			"roles": [
				"offline_access",
				"uma_authorization",
				role,
			],
		}),
	}
}

# ---------------------------------------------------------------------------
# Admin - allowed
# ---------------------------------------------------------------------------

test_allow_to_admin if {
	allow with input as produce_input_doc_by_role("tarcinapp.admin", true)
}

test_allow_to_reactions_admin if {
	allow with input as produce_input_doc_by_role("tarcinapp.reactions.admin", true)
}

test_allow_to_entityReactions_admin if {
	allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.admin", true)
}

test_allow_to_reactions_delete_admin if {
	allow with input as produce_input_doc_by_role("tarcinapp.reactions.delete.admin", true)
}

test_allow_to_entityReactions_delete_admin if {
	allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.delete.admin", true)
}

# ---------------------------------------------------------------------------
# Admin without email verification - denied
# ---------------------------------------------------------------------------

test_not_allow_to_admin_without_email_verification if {
	not allow with input as produce_input_doc_by_role("tarcinapp.admin", false)
}

test_not_allow_to_reactions_delete_admin_without_email_verification if {
	not allow with input as produce_input_doc_by_role("tarcinapp.reactions.delete.admin", false)
}

# ---------------------------------------------------------------------------
# Other roles - denied
# ---------------------------------------------------------------------------

test_not_allow_to_editor if {
	not allow with input as produce_input_doc_by_role("tarcinapp.editor", true)
}

test_not_allow_to_member if {
	not allow with input as produce_input_doc_by_role("tarcinapp.member", true)
}

test_not_allow_to_visitor if {
	not allow with input as produce_input_doc_by_role("tarcinapp.visitor", true)
}

test_not_allow_to_reactions_editor if {
	not allow with input as produce_input_doc_by_role("tarcinapp.reactions.editor", true)
}

test_not_allow_to_entityReactions_editor if {
	not allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.editor", true)
}
