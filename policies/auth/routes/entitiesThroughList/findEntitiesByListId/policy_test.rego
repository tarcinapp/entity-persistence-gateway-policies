package policies.auth.routes.entitiesThroughList.findEntitiesByListId.policy

import data.policies.util.common.test as testutil

test_allow_admin if {
    allow with input as produce_input_doc_by_role(["tarcinapp.admin"], true)
    allow with input as produce_input_doc_by_role(["tarcinapp.records.admin"], true)
    allow with input as produce_input_doc_by_role(["tarcinapp.entities.admin", "tarcinapp.lists.admin"], true)
    allow with input as produce_input_doc_by_role(["tarcinapp.records.find.admin"], true)
    allow with input as produce_input_doc_by_role(["tarcinapp.entities.find.admin", "tarcinapp.lists.find.admin"], true)
}

test_allow_editor if {
    allow with input as produce_input_doc_by_role(["tarcinapp.editor"], true)
    allow with input as produce_input_doc_by_role(["tarcinapp.records.editor"], true)
    allow with input as produce_input_doc_by_role(["tarcinapp.entities.editor", "tarcinapp.lists.editor"], true)
    allow with input as produce_input_doc_by_role(["tarcinapp.records.find.editor"], true)
    allow with input as produce_input_doc_by_role(["tarcinapp.entities.find.editor", "tarcinapp.lists.find.editor"], true)
}

test_allow_member if {
    allow with input as produce_input_doc_by_role(["tarcinapp.member"], true)
    allow with input as produce_input_doc_by_role(["tarcinapp.records.member"], true)
    allow with input as produce_input_doc_by_role(["tarcinapp.entities.member", "tarcinapp.lists.member"], true)
    allow with input as produce_input_doc_by_role(["tarcinapp.records.find.member"], true)
    allow with input as produce_input_doc_by_role(["tarcinapp.entities.find.member", "tarcinapp.lists.find.member"], true)
}

test_allow_visitor if {
    allow with input as produce_input_doc_by_role(["tarcinapp.visitor"], true)
    allow with input as produce_input_doc_by_role(["tarcinapp.records.visitor"], true)
    allow with input as produce_input_doc_by_role(["tarcinapp.entities.visitor", "tarcinapp.lists.visitor"], true)
    allow with input as produce_input_doc_by_role(["tarcinapp.records.find.visitor"], true)
    allow with input as produce_input_doc_by_role(["tarcinapp.entities.find.visitor", "tarcinapp.lists.find.visitor"], true)
}

test_not_allow_admin_unverified if {
    not allow with input as produce_input_doc_by_role(["tarcinapp.admin"], false)
    not allow with input as produce_input_doc_by_role(["tarcinapp.records.admin"], false)
    not allow with input as produce_input_doc_by_role(["tarcinapp.entities.admin", "tarcinapp.lists.admin"], false)
    not allow with input as produce_input_doc_by_role(["tarcinapp.records.find.admin"], false)
    not allow with input as produce_input_doc_by_role(["tarcinapp.entities.find.admin", "tarcinapp.lists.find.admin"], false)
}

test_not_allow_editor_unverified if {
    not allow with input as produce_input_doc_by_role(["tarcinapp.editor"], false)
    not allow with input as produce_input_doc_by_role(["tarcinapp.records.editor"], false)
    not allow with input as produce_input_doc_by_role(["tarcinapp.entities.editor", "tarcinapp.lists.editor"], false)
    not allow with input as produce_input_doc_by_role(["tarcinapp.records.find.editor"], false)
    not allow with input as produce_input_doc_by_role(["tarcinapp.entities.find.editor", "tarcinapp.lists.find.editor"], false)
}

test_not_allow_admin_on_other_records if {
    not allow with input as produce_input_doc_by_role(["tarcinapp.entities.admin"], true)
    not allow with input as produce_input_doc_by_role(["tarcinapp.lists.admin"], true)
}

test_not_allow_editor_on_other_records if {
    not allow with input as produce_input_doc_by_role(["tarcinapp.entities.editor"], true)
    not allow with input as produce_input_doc_by_role(["tarcinapp.lists.editor"], true)
}

test_not_allow_member if {
    not allow with input as produce_input_doc_by_role(["tarcinapp.member"], false)
    not allow with input as produce_input_doc_by_role(["tarcinapp.records.member"], false)
    not allow with input as produce_input_doc_by_role(["tarcinapp.entities.member", "tarcinapp.lists.member"], false)
    not allow with input as produce_input_doc_by_role(["tarcinapp.records.find.member"], false)
    not allow with input as produce_input_doc_by_role(["tarcinapp.entities.find.member", "tarcinapp.lists.find.member"], false)
}

test_not_allow_visitor if {
    not allow with input as produce_input_doc_by_role(["tarcinapp.visitor"], false)
    not allow with input as produce_input_doc_by_role(["tarcinapp.records.visitor"], false)
    not allow with input as produce_input_doc_by_role(["tarcinapp.entities.visitor", "tarcinapp.lists.visitor"], false)
    not allow with input as produce_input_doc_by_role(["tarcinapp.records.find.visitor"], false)
    not allow with input as produce_input_doc_by_role(["tarcinapp.entities.find.visitor", "tarcinapp.lists.find.visitor"], false)
}

test_not_allow_other_roles if {
    not allow with input as produce_input_doc_by_role(["tarcinapp.records.count.admin"], true)
    not allow with input as produce_input_doc_by_role(["tarcinapp.records.create.admin"], true)
    not allow with input as produce_input_doc_by_role(["tarcinapp.records.update.admin"], true)
    not allow with input as produce_input_doc_by_role(["tarcinapp.entities.count.admin"], true)
    not allow with input as produce_input_doc_by_role(["tarcinapp.entities.create.admin"], true)
    not allow with input as produce_input_doc_by_role(["tarcinapp.entities.update.admin"], true)
    not allow with input as produce_input_doc_by_role(["tarcinapp.lists.count.admin"], true)
    not allow with input as produce_input_doc_by_role(["tarcinapp.lists.create.admin"], true)
    not allow with input as produce_input_doc_by_role(["tarcinapp.lists.update.admin"], true)
    not allow with input as produce_input_doc_by_role(["tarcinapp.records.count.editor"], true)
    not allow with input as produce_input_doc_by_role(["tarcinapp.records.create.editor"], true)
    not allow with input as produce_input_doc_by_role(["tarcinapp.records.update.editor"], true)
    not allow with input as produce_input_doc_by_role(["tarcinapp.entities.count.editor"], true)
    not allow with input as produce_input_doc_by_role(["tarcinapp.entities.create.editor"], true)
    not allow with input as produce_input_doc_by_role(["tarcinapp.entities.update.editor"], true)
    not allow with input as produce_input_doc_by_role(["tarcinapp.lists.count.editor"], true)
    not allow with input as produce_input_doc_by_role(["tarcinapp.lists.create.editor"], true)
    not allow with input as produce_input_doc_by_role(["tarcinapp.lists.update.editor"], true)
    not allow with input as produce_input_doc_by_role(["tarcinapp.records.count.member"], true)
    not allow with input as produce_input_doc_by_role(["tarcinapp.records.create.member"], true)
    not allow with input as produce_input_doc_by_role(["tarcinapp.records.update.member"], true)
    not allow with input as produce_input_doc_by_role(["tarcinapp.entities.count.member"], true)
    not allow with input as produce_input_doc_by_role(["tarcinapp.entities.create.member"], true)
    not allow with input as produce_input_doc_by_role(["tarcinapp.entities.update.member"], true)
    not allow with input as produce_input_doc_by_role(["tarcinapp.lists.count.member"], true)
    not allow with input as produce_input_doc_by_role(["tarcinapp.lists.create.member"], true)
    not allow with input as produce_input_doc_by_role(["tarcinapp.lists.update.member"], true)
}

produce_input_doc_by_role(roles, is_email_verified) = test_body if {
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
            "roles": roles,
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

