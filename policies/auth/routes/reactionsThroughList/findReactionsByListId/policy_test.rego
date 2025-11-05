package policies.auth.routes.reactionsThroughList.findReactionsByListId.policy

import data.policies.util.common.test as test

test_allow_admin if {
	allow with input as produce_input_doc_by_role("tarcinapp.admin", true)
	allow with input as produce_input_doc_by_role("tarcinapp.reactions.admin", true)
	allow with input as produce_input_doc_by_role("tarcinapp.listReactions.admin", true)
	allow with input as produce_input_doc_by_role("tarcinapp.reactions.find.admin", true)
	allow with input as produce_input_doc_by_role("tarcinapp.listReactions.find.admin", true)
}

test_allow_editor if {
	allow with input as produce_input_doc_by_role("tarcinapp.editor", true)
	allow with input as produce_input_doc_by_role("tarcinapp.reactions.editor", true)
	allow with input as produce_input_doc_by_role("tarcinapp.listReactions.editor", true)
	allow with input as produce_input_doc_by_role("tarcinapp.reactions.find.editor", true)
	allow with input as produce_input_doc_by_role("tarcinapp.listReactions.find.editor", true)
}

test_allow_member if {
	allow with input as produce_input_doc_by_role("tarcinapp.member", true)
	allow with input as produce_input_doc_by_role("tarcinapp.reactions.member", true)
	allow with input as produce_input_doc_by_role("tarcinapp.listReactions.member", true)
	allow with input as produce_input_doc_by_role("tarcinapp.reactions.find.member", true)
	allow with input as produce_input_doc_by_role("tarcinapp.listReactions.find.member", true)
}

test_allow_visitor if {
	allow with input as produce_input_doc_by_role("tarcinapp.visitor", true)
	allow with input as produce_input_doc_by_role("tarcinapp.reactions.visitor", true)
	allow with input as produce_input_doc_by_role("tarcinapp.listReactions.visitor", true)
	allow with input as produce_input_doc_by_role("tarcinapp.reactions.find.visitor", true)
	allow with input as produce_input_doc_by_role("tarcinapp.listReactions.find.visitor", true)
}

test_not_allow_member if {
	not allow with input as produce_input_doc_by_role("tarcinapp.member", false)
	not allow with input as produce_input_doc_by_role("tarcinapp.reactions.member", false)
	not allow with input as produce_input_doc_by_role("tarcinapp.listReactions.member", false)
	not allow with input as produce_input_doc_by_role("tarcinapp.reactions.find.member", false)
	not allow with input as produce_input_doc_by_role("tarcinapp.listReactions.find.member", false)
}

test_not_allow_visitor if {
	not allow with input as produce_input_doc_by_role("tarcinapp.visitor", false)
	not allow with input as produce_input_doc_by_role("tarcinapp.reactions.visitor", false)
	not allow with input as produce_input_doc_by_role("tarcinapp.listReactions.visitor", false)
	not allow with input as produce_input_doc_by_role("tarcinapp.reactions.find.visitor", false)
	not allow with input as produce_input_doc_by_role("tarcinapp.listReactions.find.visitor", false)
}

test_not_allow_other_roles if {
	# Ensure 'records' scoped roles do not grant access to reactions/listReactions
	not allow with input as produce_input_doc_by_role("tarcinapp.records.admin", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.records.find.admin", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.records.editor", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.records.find.editor", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.records.member", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.records.find.member", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.records.visitor", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.records.find.visitor", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.records.count.admin", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.records.create.admin", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.records.update.admin", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.records.count.editor", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.records.create.editor", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.records.update.editor", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.records.count.member", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.records.create.member", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.records.update.member", true)

	# reactions-scoped operational roles should not grant 'find' either here
	not allow with input as produce_input_doc_by_role("tarcinapp.reactions.count.admin", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.reactions.create.admin", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.reactions.update.admin", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.listReactions.count.admin", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.listReactions.create.admin", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.listReactions.update.admin", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.reactions.count.editor", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.reactions.create.editor", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.reactions.update.editor", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.listReactions.count.editor", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.listReactions.create.editor", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.listReactions.update.editor", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.reactions.count.member", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.reactions.create.member", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.reactions.update.member", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.listReactions.count.member", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.listReactions.create.member", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.listReactions.update.member", true)
}

produce_input_doc_by_role(role, is_email_verified) := test_body if {
	test_body = {
		"appShortcode": "tarcinapp",
		"httpMethod": "GET",
		"requestPath": "/lists/123/reactions",
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
