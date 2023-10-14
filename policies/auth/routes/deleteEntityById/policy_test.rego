package policies.auth.routes.deleteEntityById.policy

import data.policies.util.common.test as test

test_allow_to_admin {

    allow 
        with input as produce_input_doc_by_role(["tarcinapp.admin"])

    allow 
        with input as produce_input_doc_by_role(["tarcinapp.records.admin"])

    allow 
        with input as produce_input_doc_by_role(["tarcinapp.entities.admin"])

    allow 
        with input as produce_input_doc_by_role(["tarcinapp.records.delete.admin"])

    allow 
        with input as produce_input_doc_by_role(["tarcinapp.entities.delete.admin"])
}

test_not_allow_to_any_other_roles {
    not allow 
        with input as produce_input_doc_by_role(["tarcinapp.editor"])
    
    not allow 
        with input as produce_input_doc_by_role(["tarcinapp.member"])

    not allow 
        with input as produce_input_doc_by_role(["tarcinapp.visitor"])
}

produce_input_doc_by_role(roles) = test_body {
    test_body = {
        "appShortcode":"tarcinapp",
		"httpMethod": "POST",
		"requestPath": "/generic-entities",
		"queryParams": {},
		"encodedJwt": test.produce_token({
			"sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
			"name": "John Doe",
			"admin": true,
			"iat": 1516239022,
			"email_verified": true,
			"groups": [],
			"roles": roles,
		}),
        "requestPayload": {}
	}
}