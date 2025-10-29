package policies.auth.routes.entityReactions.findEntityReactions.policy

import data.policies.util.common.test as test

test_allow_admin if {
	allow with input as produce_input_doc_by_role("tarcinapp.admin", true)
    allow with input as produce_input_doc_by_role("tarcinapp.reactions.admin", true)
    allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.admin", true)
    allow with input as produce_input_doc_by_role("tarcinapp.reactions.find.admin", true)
    allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.find.admin", true)
}

test_allow_editor if {
    allow with input as produce_input_doc_by_role("tarcinapp.editor", true)
    allow with input as produce_input_doc_by_role("tarcinapp.reactions.editor", true)
    allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.editor", true)
    allow with input as produce_input_doc_by_role("tarcinapp.reactions.find.editor", true)
    allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.find.editor", true)
}

test_allow_member if {
    allow with input as produce_input_doc_by_role("tarcinapp.member", true)
    allow with input as produce_input_doc_by_role("tarcinapp.reactions.member", true)
    allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.member", true)
    allow with input as produce_input_doc_by_role("tarcinapp.reactions.find.member", true)
    allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.find.member", true)
}

test_allow_visitor if {
    allow with input as produce_input_doc_by_role("tarcinapp.visitor", true)
    allow with input as produce_input_doc_by_role("tarcinapp.reactions.visitor", true)
    allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.visitor", true)
    allow with input as produce_input_doc_by_role("tarcinapp.reactions.find.visitor", true)
    allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.find.visitor", true)
}

test_not_allow_member if {
    not allow with input as produce_input_doc_by_role("tarcinapp.member", false)
    not allow with input as produce_input_doc_by_role("tarcinapp.reactions.member", false)
    not allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.member", false)
    not allow with input as produce_input_doc_by_role("tarcinapp.reactions.find.member", false)
    not allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.find.member", false)
}

test_not_allow_visitor if {
    not allow with input as produce_input_doc_by_role("tarcinapp.visitor", false)
    not allow with input as produce_input_doc_by_role("tarcinapp.reactions.visitor", false)
    not allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.visitor", false)
    not allow with input as produce_input_doc_by_role("tarcinapp.reactions.find.visitor", false)
    not allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.find.visitor", false)
}

test_not_allow_other_roles if {
    # Ensure 'records' scoped roles do not grant access to reactions
    not allow with input as produce_input_doc_by_role("tarcinapp.records.admin", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.find.admin", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.editor", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.find.editor", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.member", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.find.member", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.visitor", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.find.visitor", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.count.admin", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.create.admin", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.update.admin", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.count.editor", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.create.editor", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.update.editor", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.count.member", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.create.member", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.records.update.member", true)

    # reactions-scoped roles
    not allow with input as produce_input_doc_by_role("tarcinapp.reactions.count.admin", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.reactions.create.admin", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.reactions.update.admin", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.count.admin", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.create.admin", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.update.admin", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.reactions.count.editor", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.reactions.create.editor", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.reactions.update.editor", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.count.editor", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.create.editor", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.update.editor", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.reactions.count.member", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.reactions.create.member", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.reactions.update.member", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.count.member", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.create.member", true)
    not allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.update.member", true)
}


produce_input_doc_by_role(role, is_email_verified) = test_body if {
    test_body = {
        "appShortcode": "tarcinapp",
        "httpMethod": "GET",
        "requestPath": "/entityReactions",
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
