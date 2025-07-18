package policies.auth.routes.updateAllEntities.policy

import data.policies.util.common.test as test

# Refactored to accept a full requestPayload
produce_input_doc_by_role(role, is_email_verified) = test_body if {
    test_body := produce_input_doc_by_role_with_payload(role, is_email_verified, base_payload)
}

produce_input_doc_by_role_with_payload(role, is_email_verified, requestPayload) = test_body if {
    test_body = {
        "appShortcode": "tarcinapp",
        "httpMethod": "PUT",
        "requestPath": "/generic-entities",
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
        "requestPayload": requestPayload
    }
}

# Helper for default payload
base_payload = {
    "_name": "test entity",
    "description": "test description",
    "_visibility": "public",
    "_ownerUsers": ["any-owner"],
    "_ownerGroups": ["any-owner-group"],
    "_validFromDateTime": "2020-01-01T00:00:00Z",
    "_validUntilDateTime": null
}

# Update all test cases to use the new function signature

test_allow_to_admin if {
    allow with input as produce_input_doc_by_role("tarcinapp.admin", true)
}

test_allow_to_records_admin if {
    allow with input as produce_input_doc_by_role("tarcinapp.records.admin", true)
}

test_allow_to_entities_admin if {
    allow with input as produce_input_doc_by_role("tarcinapp.entities.admin", true)
}

test_not_allow_to_admin_without_email_verification if {
    not allow with input as produce_input_doc_by_role("tarcinapp.admin", false)
}

test_allow_to_editor if {
    allow with input as produce_input_doc_by_role("tarcinapp.editor", true)
}

test_allow_to_records_editor if {
    allow with input as produce_input_doc_by_role("tarcinapp.records.editor", true)
}

test_allow_to_entities_editor if {
    allow with input as produce_input_doc_by_role("tarcinapp.entities.editor", true)
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

test_not_allow_to_non_admin_editor_roles_member if {
    not allow with input as produce_input_doc_by_role("tarcinapp.member", true)
}

test_not_allow_to_non_admin_editor_roles_visitor if {
    not allow with input as produce_input_doc_by_role("tarcinapp.visitor", true)
}

test_not_allow_to_non_admin_editor_roles_records_member if {
    not allow with input as produce_input_doc_by_role("tarcinapp.records.member", true)
}

test_not_allow_to_non_admin_editor_roles_entities_member if {
    not allow with input as produce_input_doc_by_role("tarcinapp.entities.member", true)
}

test_not_allow_to_non_admin_editor_roles_records_visitor if {
    not allow with input as produce_input_doc_by_role("tarcinapp.records.visitor", true)
}

test_not_allow_to_non_admin_editor_roles_entities_visitor if {
    not allow with input as produce_input_doc_by_role("tarcinapp.entities.visitor", true)
}

# Forbidden field test

test_not_allow_to_editor_with_forbidden_field if {
    forbidden_payload := object.union(base_payload, {"_creationDateTime": "2020-01-01T00:00:00Z"})
    not allow with input as produce_input_doc_by_role_with_payload("tarcinapp.editor", true, forbidden_payload)
}