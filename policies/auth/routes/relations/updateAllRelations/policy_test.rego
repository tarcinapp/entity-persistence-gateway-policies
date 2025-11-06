package policies.auth.routes.relations.updateAllRelations.policy

import data.policies.util.common.test as test

test_allow_to_admin if {
	allow with input as produce_input_doc_by_role(["tarcinapp.admin"])

	allow with input as produce_input_doc_by_role(["tarcinapp.records.admin"])

	allow with input as produce_input_doc_by_role(["tarcinapp.relations.admin"])

	allow with input as produce_input_doc_by_role(["tarcinapp.records.update.admin"])

	allow with input as produce_input_doc_by_role(["tarcinapp.relations.update.admin"])
}

test_allow_to_editor if {
	allow with input as produce_input_doc_by_role(["tarcinapp.editor"])

	allow with input as produce_input_doc_by_role(["tarcinapp.records.editor"])

	allow with input as produce_input_doc_by_role(["tarcinapp.relations.editor"])

	allow with input as produce_input_doc_by_role(["tarcinapp.records.update.editor"])

	allow with input as produce_input_doc_by_role(["tarcinapp.relations.update.editor"])
}

test_not_allow_to_any_other_roles if {
	not allow with input as produce_input_doc_by_role(["tarcinapp.member"])

	not allow with input as produce_input_doc_by_role(["tarcinapp.visitor"])
}

produce_input_doc_by_role(roles) := test_body if {
	test_body = {
		"appShortcode": "tarcinapp",
		"httpMethod": "PUT",
		"requestPath": "/relations",
		"queryParams": {},
		"encodedJwt": test.produce_token({
			"sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
			"name": "John Doe",
			"admin": true,
			"iat": 1516239022,
			"email_verified": true,
			"groups": ["my-group"],
			"roles": roles,
		}),
		"requestPayload": {
			"id": "123",
			"relationType": "parent",
			"targetId": "456",
		},
	}
}
