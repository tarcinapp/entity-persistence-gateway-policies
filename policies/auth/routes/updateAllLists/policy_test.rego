package policies.auth.routes.updateAllLists.policy

import data.policies.util.common.test as test

test_allow_to_admin if {
    allow with input as produce_input_doc_by_role("tarcinapp.admin", true)
}

test_not_allow_to_admin_without_email_verification if {
    not allow with input as produce_input_doc_by_role("tarcinapp.admin", false)
}

test_allow_to_editor if {
    allow with input as produce_input_doc_by_role("tarcinapp.editor", true)
}

test_not_allow_to_editor_without_email_verification if {
    not allow with input as produce_input_doc_by_role("tarcinapp.editor", false)
}

test_not_allow_to_member if {
    not allow with input as produce_input_doc_by_role("tarcinapp.member", true)
}

test_not_allow_to_member_email_verification if {
    not allow with input as produce_input_doc_by_role("tarcinapp.member", false)
}

test_not_allow_to_visitor if {
    not allow with input as produce_input_doc_by_role("tarcinapp.visitor", true)
}

test_allow_to_admin_patterns if {
    allow with input as produce_input_doc_by_role("tarcinapp.admin", true)
}

test_allow_to_admin_patterns_records if {
    allow with input as produce_input_doc_by_role("tarcinapp.records.update.admin", true)
}

test_allow_to_admin_patterns_lists if {
    allow with input as produce_input_doc_by_role("tarcinapp.lists.update.admin", true)
}

test_allow_to_editor_patterns if {
    allow with input as produce_input_doc_by_role("tarcinapp.editor", true)
}

test_allow_to_editor_patterns_records if {
    allow with input as produce_input_doc_by_role("tarcinapp.records.update.editor", true)
}

test_allow_to_editor_patterns_lists if {
    allow with input as produce_input_doc_by_role("tarcinapp.lists.update.editor", true)
}

test_not_allow_to_non_admin_editor_roles if {
    not allow with input as produce_input_doc_by_role("tarcinapp.member", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.visitor", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.member", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.entities.member", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.visitor", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.entities.visitor", true)
}

produce_input_doc_by_role(role, is_email_verified) = test_body if {
    test_body = {
        "appShortcode":"tarcinapp",
        "httpMethod": "PUT",
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
        "requestPayload": {
			"_id": "123",
			"_name": "test list",
			"_visibility": "public",
			"_ownerUsers": ["any-owner"],
			"_ownerGroups": ["any-owner-group"],
			"_validFromDateTime": "2020-01-01T00:00:00Z",
			"_validUntilDateTime": null
		}
    }
}