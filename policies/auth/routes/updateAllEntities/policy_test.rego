package policies.auth.routes.updateAllEntities.policy

test_allow_to_admin if {
    allow with input as produce_input_doc_by_role("tarcinapp.admin", true)
}

test_allow_to_editor if {
    allow with input as produce_input_doc_by_role("tarcinapp.editor", true)
}

test_not_allow_to_editor_by_forbidden_field if {
    not allow with input as produce_input_doc_by_role("tarcinapp.editor", true)
}

test_allow_to_member if {
    allow with input as produce_input_doc_by_role("tarcinapp.member", true)
}

test_allow_to_correct_group if {
    allow with input as produce_input_doc_by_role("tarcinapp.member", true)
}

test_not_allow_to_member_email_verification if {
    not allow with input as produce_input_doc_by_role("tarcinapp.member", false)
}

test_not_allow_to_member_by_forbidden_field if {
    not allow with input as produce_input_doc_by_role("tarcinapp.member", true)
}

test_not_allow_to_member_by_invalid_group if {
    not allow with input as produce_input_doc_by_role("tarcinapp.member", true)
}

test_not_allow_to_visitor if {
    not allow with input as produce_input_doc_by_role("tarcinapp.visitor", true)
}

produce_input_doc_by_role(role, is_email_verified) = test_body if {
    test_body = {
        "appShortcode":"tarcinapp",
		"httpMethod": "PUT",
		"requestPath": "/generic-entities",
		"queryParams": {},
		"encodedJwt": produce_token({
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
        "requestPayload": {
			"id": "123",
			"name": "test entity",
			"description": "test description",
			"visibility": "public",
			"ownerUsers": ["any-owner"],
			"ownerGroups": ["any-owner-group"],
			"validFromDateTime": "2020-01-01T00:00:00Z",
			"validUntilDateTime": null
		}
	}
}

produce_token(payload) = token if {
	token = {
		"payload": payload
	}
}