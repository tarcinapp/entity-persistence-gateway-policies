package policies.auth.routes.findLists.policy

import data.policies.util.common.test as test

test_allow_admin {
	allow with input as produce_input_doc_by_role("tarcinapp.admin", true)
    allow with input as produce_input_doc_by_role("tarcinapp.records.admin", true)
    allow with input as produce_input_doc_by_role("tarcinapp.lists.admin", true)
    allow with input as produce_input_doc_by_role("tarcinapp.records.find.admin", true)
    allow with input as produce_input_doc_by_role("tarcinapp.lists.find.admin", true)
}

test_allow_editor {
	allow with input as produce_input_doc_by_role("tarcinapp.editor", true)
    allow with input as produce_input_doc_by_role("tarcinapp.records.editor", true)
    allow with input as produce_input_doc_by_role("tarcinapp.lists.editor", true)
    allow with input as produce_input_doc_by_role("tarcinapp.records.find.editor", true)
    allow with input as produce_input_doc_by_role("tarcinapp.lists.find.editor", true)
}

test_allow_member {
	allow with input as produce_input_doc_by_role("tarcinapp.member", true)
    allow with input as produce_input_doc_by_role("tarcinapp.records.member", true)
    allow with input as produce_input_doc_by_role("tarcinapp.lists.member", true)
    allow with input as produce_input_doc_by_role("tarcinapp.records.find.member", true)
    allow with input as produce_input_doc_by_role("tarcinapp.lists.find.member", true)
}

test_allow_visitor {
	allow with input as produce_input_doc_by_role("tarcinapp.visitor", true)
    allow with input as produce_input_doc_by_role("tarcinapp.records.visitor", true)
    allow with input as produce_input_doc_by_role("tarcinapp.lists.visitor", true)
    allow with input as produce_input_doc_by_role("tarcinapp.records.find.visitor", true)
    allow with input as produce_input_doc_by_role("tarcinapp.lists.find.visitor", true)
}

test_not_allow_member {
	not allow with input as produce_input_doc_by_role("tarcinapp.member", false)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.member", false)
    not allow with input as produce_input_doc_by_role("tarcinapp.lists.member", false)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.find.member", false)
    not allow with input as produce_input_doc_by_role("tarcinapp.lists.find.member", false)
}

test_not_allow_visitor {
	not allow with input as produce_input_doc_by_role("tarcinapp.visitor", false)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.visitor", false)
    not allow with input as produce_input_doc_by_role("tarcinapp.lists.visitor", false)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.find.visitor", false)
    not allow with input as produce_input_doc_by_role("tarcinapp.lists.find.visitor", false)
}

test_not_allow_other_roles {
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


produce_input_doc_by_role(role, is_email_verified) = test_body {
    test_body = {
		"httpMethod": "POST",
		"requestPath": "/lists",
		"queryParams": {},
		"encodedJwt": test.produce_token({
			"sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
			"name": "Favorites",
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
