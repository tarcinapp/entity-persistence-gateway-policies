package policies.auth.routes.entityReactions.countEntityReactions.policy

import data.policies.util.common.test as test

# Expanded tests for countEntityReactions based on findEntityReactions patterns.

test_allow_admin if {
	allow with input as produce_input_doc_by_role("tarcinapp.admin", true)
	allow with input as produce_input_doc_by_role("tarcinapp.reactions.admin", true)
	allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.admin", true)
	allow with input as produce_input_doc_by_role("tarcinapp.reactions.count.admin", true)
	allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.count.admin", true)
}

test_allow_editor if {
	allow with input as produce_input_doc_by_role("tarcinapp.editor", true)
	allow with input as produce_input_doc_by_role("tarcinapp.reactions.editor", true)
	allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.editor", true)
	allow with input as produce_input_doc_by_role("tarcinapp.reactions.count.editor", true)
	allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.count.editor", true)
}

test_allow_member if {
	allow with input as produce_input_doc_by_role("tarcinapp.member", true)
	allow with input as produce_input_doc_by_role("tarcinapp.reactions.member", true)
	allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.member", true)
	allow with input as produce_input_doc_by_role("tarcinapp.reactions.count.member", true)
	allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.count.member", true)
}

test_allow_visitor if {
	allow with input as produce_input_doc_by_role("tarcinapp.visitor", true)
	allow with input as produce_input_doc_by_role("tarcinapp.reactions.visitor", true)
	allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.visitor", true)
	allow with input as produce_input_doc_by_role("tarcinapp.reactions.count.visitor", true)
	allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.count.visitor", true)
}

test_not_allow_member if {
	not allow with input as produce_input_doc_by_role("tarcinapp.member", false)
	not allow with input as produce_input_doc_by_role("tarcinapp.reactions.member", false)
	not allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.member", false)
	not allow with input as produce_input_doc_by_role("tarcinapp.reactions.count.member", false)
	not allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.count.member", false)
}

test_not_allow_visitor if {
	not allow with input as produce_input_doc_by_role("tarcinapp.visitor", false)
	not allow with input as produce_input_doc_by_role("tarcinapp.reactions.visitor", false)
	not allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.visitor", false)
	not allow with input as produce_input_doc_by_role("tarcinapp.reactions.count.visitor", false)
	not allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.count.visitor", false)
}

test_not_allow_other_roles if {
	# Ensure 'records' scoped roles do not grant access to reactions count
	not allow with input as produce_input_doc_by_role("tarcinapp.records.admin", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.records.count.admin", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.records.create.admin", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.records.update.admin", true)

	# find/create/update scoped roles for reactions/entityReactions should NOT grant count
	not allow with input as produce_input_doc_by_role("tarcinapp.reactions.find.admin", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.reactions.create.admin", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.reactions.update.admin", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.find.admin", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.create.admin", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.update.admin", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.reactions.find.editor", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.find.editor", true)
}

produce_input_doc_by_role(role, is_email_verified) := test_body if {
	test_body = {
		"appShortcode": "tarcinapp",
		"httpMethod": "GET",
		"requestPath": "/entityReactions",
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
