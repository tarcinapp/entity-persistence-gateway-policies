package policies.auth.routes.updateAllLists.policy

import data.policies.util.common.test as test

test_allow_to_admin if {
    allow with input as test.produce_input_doc_by_role("tarcinapp.admin", true)
}

test_allow_to_editor if {
    allow with input as test.produce_input_doc_by_role("tarcinapp.editor", true)
}

test_not_allow_to_editor_by_forbidden_field if {
    not allow with input as test.produce_input_doc_by_role("tarcinapp.editor", true)
}

test_allow_to_member if {
    allow with input as test.produce_input_doc_by_role("tarcinapp.member", true)
}

test_allow_to_correct_group if {
    allow with input as test.produce_input_doc_by_role("tarcinapp.member", true)
}

test_not_allow_to_member_email_verification if {
    not allow with input as test.produce_input_doc_by_role("tarcinapp.member", false)
}

test_not_allow_to_member_by_forbidden_field if {
    not allow with input as test.produce_input_doc_by_role("tarcinapp.member", true)
}

test_not_allow_to_member_by_invalid_group if {
    not allow with input as test.produce_input_doc_by_role("tarcinapp.member", true)
}

test_not_allow_to_visitor if {
    not allow with input as test.produce_input_doc_by_role("tarcinapp.visitor", true)
}

test_not_allow_to_any_other_roles if {
    not allow with input as test.produce_input_doc_by_role("tarcinapp.editor", true)
    not allow with input as test.produce_input_doc_by_role("tarcinapp.member", true)
    not allow with input as test.produce_input_doc_by_role("tarcinapp.visitor", true)
}

produce_input_doc_by_role(roles) = test_body if {
    test_body = {
        "appShortcode":"tarcinapp",
        "httpMethod": "POST",
        "requestPath": "/lists",
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