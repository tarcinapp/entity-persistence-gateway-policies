package policies.auth.routes.createEntity.policy

import data.policies.util.common.test as test
import data.policies.fields.genericentities.policy as forbidden_fields

# Forbidden fields are always mocked in this test
# Tests of forbidden field generation is implemented in its own package

# In this test, we try to create a generic entity with admin role.
# We expect 'allow' rule to be true
test_allow_to_admin if {
    allow with input as produce_input_doc_by_role("tarcinapp.entities.create.admin", true, {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "public",
        "_createdDateTime": "2025-01-01T00:00:00Z"
    })
}

test_allow_to_editor if {
    allow with input as produce_input_doc_by_role("tarcinapp.entities.create.editor", true, {
        "_name": "Test Entity",
        "_description": "Test Description",
        "_visibility": "public"
    })
}

test_not_allow_to_editor_by_forbidden_field if {
    not allow with input as produce_input_doc_by_role("tarcinapp.entities.create.editor", true, {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "public",
        "_createdBy": "some-user"  # This should be forbidden for editors
    })
}

test_allow_to_member if {
    allow with input as produce_input_doc_by_role("tarcinapp.entities.create.member", true, {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "public"
    })
}

# In this scenario, user is member of group-1 and group-2
# He is trying to create an entity belongs to group-1
# We expect this operation to be allowed.
test_allow_to_correct_group if {
    allow with input as produce_input_doc_by_role("tarcinapp.entities.create.member", true, {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerGroups": ["group-1"]  # User belongs to group-1
    })
}

test_not_allow_to_member_email_verification if {
    not allow with input as produce_input_doc_by_role("tarcinapp.entities.create.member", false, {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "public"
    })
}

test_not_allow_to_member_by_forbidden_field if {
    not allow with input as produce_input_doc_by_role("tarcinapp.entities.create.member", true, {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "public",
        "_createdBy": "some-user"  # This should be forbidden for members
    })
}

# In this test we try to create an entity as a member
# As the scenario, our user is member of group-1 but he tries to create an entity
# belongs to group-2.
# We expect this operation to not allowed
test_not_allow_to_member_by_invalid_group if {
    not allow with input as produce_input_doc_by_role("tarcinapp.entities.create.member", true, {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "public",
        "_ownerGroups": ["group-2"]  # User doesn't belong to group-2
    })
}

test_not_allow_to_visitor if {
    not allow with input as produce_input_doc_by_role("tarcinapp.entities.create.visitor", true, {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "public"
    })
}

produce_input_doc_by_role(roles, is_email_verified, requestPayload) = test_body if {
    test_body = {
        "appShortcode": "tarcinapp",
        "httpMethod": "POST",
        "requestPath": "/generic-entities",
        "queryParams": {},
        "encodedJwt": test.produce_token({
            "sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
            "name": "John Doe",
            "admin": true,
            "iat": 1516239022,
            "email_verified": is_email_verified,
            "groups": ["group-1"],
            "roles": [roles],
        }),
        "requestPayload": requestPayload
    }
}