package policies.auth.routes.entitiesThroughList.findEntitiesByListId.policy

import data.policies.util.common.test as testutil

test_allow_admin if {
    allow with input as produce_input_doc_by_role("tarcinapp.admin", true)
    allow with input as produce_input_doc_by_role("tarcinapp.records.admin", true)
    allow with input as produce_input_doc_by_role("tarcinapp.entities.admin", true)
    allow with input as produce_input_doc_by_role("tarcinapp.records.find.admin", true)
    allow with input as produce_input_doc_by_role("tarcinapp.entities.find.admin", true)
}

test_allow_editor if {
    allow with input as produce_input_doc_by_role("tarcinapp.editor", true)
    allow with input as produce_input_doc_by_role("tarcinapp.records.editor", true)
    allow with input as produce_input_doc_by_role("tarcinapp.entities.editor", true)
    allow with input as produce_input_doc_by_role("tarcinapp.records.find.editor", true)
    allow with input as produce_input_doc_by_role("tarcinapp.entities.find.editor", true)
}

test_allow_member if {
    allow with input as produce_input_doc_by_role("tarcinapp.member", true)
    allow with input as produce_input_doc_by_role("tarcinapp.records.member", true)
    allow with input as produce_input_doc_by_role("tarcinapp.entities.member", true)
    allow with input as produce_input_doc_by_role("tarcinapp.records.find.member", true)
    allow with input as produce_input_doc_by_role("tarcinapp.entities.find.member", true)
}

test_allow_visitor if {
    allow with input as produce_input_doc_by_role("tarcinapp.visitor", true)
    allow with input as produce_input_doc_by_role("tarcinapp.records.visitor", true)
    allow with input as produce_input_doc_by_role("tarcinapp.entities.visitor", true)
    allow with input as produce_input_doc_by_role("tarcinapp.records.find.visitor", true)
    allow with input as produce_input_doc_by_role("tarcinapp.entities.find.visitor", true)
}

test_not_allow_member if {
    not allow with input as produce_input_doc_by_role("tarcinapp.member", false)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.member", false)
    not allow with input as produce_input_doc_by_role("tarcinapp.entities.member", false)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.find.member", false)
    not allow with input as produce_input_doc_by_role("tarcinapp.entities.find.member", false)
}

test_not_allow_visitor if {
    not allow with input as produce_input_doc_by_role("tarcinapp.visitor", false)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.visitor", false)
    not allow with input as produce_input_doc_by_role("tarcinapp.entities.visitor", false)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.find.visitor", false)
    not allow with input as produce_input_doc_by_role("tarcinapp.entities.find.visitor", false)
}

test_not_allow_other_roles if {
    not allow with input as produce_input_doc_by_role("tarcinapp.records.count.admin", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.create.admin", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.update.admin", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.entities.count.admin", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.entities.create.admin", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.entities.update.admin", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.count.editor", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.create.editor", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.update.editor", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.entities.count.editor", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.entities.create.editor", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.entities.update.editor", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.count.member", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.create.member", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.update.member", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.entities.count.member", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.entities.create.member", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.entities.update.member", true)
}

produce_input_doc_by_role(role, is_email_verified) = test_body if {
    test_body = {
        "appShortcode": "tarcinapp",
        "httpMethod": "POST",
        "requestPath": "/entities",
        "queryParams": {},
        "encodedJwt": data.policies.util.common.test.produce_token({
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
        "originalRecord": {
            "name": "any-record",
            "_ownerUsers": [],
            "_ownerGroups": [],
            "_visibility": "public",
            "_validFromDateTime": "2020-01-01T00:00:00Z",
            "_validUntilDateTime": null
        },
    }
}

