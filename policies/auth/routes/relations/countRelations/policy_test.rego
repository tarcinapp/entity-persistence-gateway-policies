package policies.auth.routes.relations.countRelations.policy

import data.policies.util.common.test as test

test_allow_admin if {
	allow with input as produce_input_doc_by_role("tarcinapp.admin", true)
	allow with input as produce_input_doc_by_role("tarcinapp.relations.admin", true)
	allow with input as produce_input_doc_by_role("tarcinapp.relations.count.admin", true)
}

test_allow_editor if {
	allow with input as produce_input_doc_by_role("tarcinapp.editor", true)
	allow with input as produce_input_doc_by_role("tarcinapp.relations.editor", true)
	allow with input as produce_input_doc_by_role("tarcinapp.relations.count.editor", true)
}

test_allow_member if {
	allow with input as produce_input_doc_by_role("tarcinapp.member", true)
	allow with input as produce_input_doc_by_role("tarcinapp.relations.member", true)
	allow with input as produce_input_doc_by_role("tarcinapp.relations.count.member", true)
}

test_allow_visitor if {
	allow with input as produce_input_doc_by_role("tarcinapp.visitor", true)
	allow with input as produce_input_doc_by_role("tarcinapp.relations.visitor", true)
	allow with input as produce_input_doc_by_role("tarcinapp.relations.count.visitor", true)
}

test_not_allow_member if {
	not allow with input as produce_input_doc_by_role("tarcinapp.member", false)
	not allow with input as produce_input_doc_by_role("tarcinapp.relations.member", false)
	not allow with input as produce_input_doc_by_role("tarcinapp.relations.count.member", false)
}

test_not_allow_visitor if {
	not allow with input as produce_input_doc_by_role("tarcinapp.visitor", false)
	not allow with input as produce_input_doc_by_role("tarcinapp.relations.visitor", false)
	not allow with input as produce_input_doc_by_role("tarcinapp.relations.count.visitor", false)
}

test_not_allow_other_roles if {
	not allow with input as produce_input_doc_by_role("tarcinapp.records.find.admin", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.records.create.admin", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.records.update.admin", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.relations.find.admin", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.relations.create.admin", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.relations.update.admin", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.records.find.editor", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.records.create.editor", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.records.update.editor", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.relations.find.editor", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.relations.create.editor", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.relations.update.editor", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.records.find.member", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.records.create.member", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.records.update.member", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.relations.find.member", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.relations.create.member", true)
	not allow with input as produce_input_doc_by_role("tarcinapp.relations.update.member", true)
}

produce_input_doc_by_role(role, is_email_verified) := test_body if {
	test_body = {
		"appShortcode": "tarcinapp",
		"httpMethod": "POST",
		"requestPath": "/relations",
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
