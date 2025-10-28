package policies.auth.routes.lists.findLists.policy

import data.policies.util.common.test as test

test_allow_to_admin if {
    allow with input as produce_input_doc_by_role("tarcinapp.admin", true)
}

test_allow_to_editor if {
    allow with input as produce_input_doc_by_role("tarcinapp.editor", true)
}

test_allow_to_member if {
    allow with input as produce_input_doc_by_role("tarcinapp.member", true)
}

test_not_allow_to_member_email_verification if {
    not allow with input as produce_input_doc_by_role("tarcinapp.member", false)
}

test_allow_to_visitor if {
    allow with input as produce_input_doc_by_role("tarcinapp.visitor", true)
}

test_not_allow_other_roles if {
    not allow with input as produce_input_doc_by_role("tarcinapp.records.count.admin", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.create.admin", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.update.admin", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.lists.count.admin", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.lists.create.admin", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.lists.update.admin", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.count.editor", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.create.editor", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.update.editor", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.lists.count.editor", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.lists.create.editor", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.lists.update.editor", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.count.member", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.create.member", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.update.member", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.lists.count.member", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.lists.create.member", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.lists.update.member", true)
}

produce_input_doc_by_role(role, is_email_verified) = test_body if {
    test_body = {
		"appShortcode": "tarcinapp",
		"httpMethod": "GET",
		"requestPath": "/lists",
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
