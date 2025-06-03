package policies.auth.routes.createList.policy

import data.policies.util.common.test as test
import data.policies.fields.lists.policy as forbidden_fields

# Forbidden fields are always mocked in this test
# Tests of forbidden field generation is implemented in its own package

# In this test, we try to create a generic list with admin role.
# We expect 'allow' rule to be true
test_allow_to_admin if {
    allow 
        with input as produce_input_doc_by_role(
            ["tarcinapp.admin"],
            [],
            true, 
            {
                "name": "test list",
                "ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"]
            })

        with data.policies.fields.lists.policy as {
            "which_fields_forbidden_for_create": []
        }
}

test_allow_to_editor if {
    allow 
        with input as produce_input_doc_by_role(
            ["tarcinapp.editor"],
            [],
            true, 
            {
                "name": "test list",
                "ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"]
            })

        with data.policies.fields.lists.policy as {
            "which_fields_forbidden_for_create": []
        }
}

test_not_allow_to_editor_by_forbidden_field if {
    not allow 
        with input as produce_input_doc_by_role(
            ["tarcinapp.editor"],
            [],
            true, 
            {
                "name": "test list",
                "ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
                "invalid_field_for_editors": 1
            })

        with data.policies.fields.lists.policy as {
            "which_fields_forbidden_for_create": ["invalid_field_for_editors"]
        }
}

test_allow_to_member if {
    allow 
        with input as produce_input_doc_by_role(
            ["tarcinapp.member"],
            [],
            true, 
            {
                "name": "test list"
            })

        with data.policies.fields.lists.policy as {
            "which_fields_forbidden_for_create": []
        }
}

# In this scenario, user is member of group-1 and group-2
# He is trying to create an list belongs to group-1
# We expect this operation to be allowed.
test_allow_to_correct_group if {
    allow 
        with input as produce_input_doc_by_role(
            ["tarcinapp.member"],
            ["group-1", "group-2"],
            true, 
            {
                "name": "test list",
                "ownerGroups": ["group-1"]
            })

        with data.policies.fields.lists.policy as {
            "which_fields_forbidden_for_create": []
        }
}

test_not_allow_to_member_email_verification if {
    not allow 
        with input as produce_input_doc_by_role(
            ["tarcinapp.member"],
            [],
            false, 
            {
                "name": "test list"
            })

        with data.policies.fields.lists.policy as {
            "which_fields_forbidden_for_create": []
        }
}

test_not_allow_to_member_by_forbidden_field if {
    not allow 
        with input as produce_input_doc_by_role(
            ["tarcinapp.member"],
            [],
            false, 
            {
                "name": "test list",
                "ownerUsers": ["me"]
            })

        with data.policies.fields.lists.policy as {
            "which_fields_forbidden_for_create": ["ownerUsers"]
        }
}

# In this test we try to create an list as a member
# As the scenario, our user is member of group-1 but he tries to create an list
# belongs to group-2.
# We expect this operation to not allowed
test_not_allow_to_member_by_invalid_group if {
    not allow 
        with input as produce_input_doc_by_role(
            ["tarcinapp.member"],
            ["group-1"],
            false, 
            {
                "name": "test list",
                "ownerGroups": ["group-2"]
            })

        with data.policies.fields.lists.policy as {
            "which_fields_forbidden_for_create": []
        }
}

test_not_allow_to_visitor if {
    not allow 
        with input as produce_input_doc_by_role(
            ["tarcinapp.visitor"],
            [],
            true, 
            {
                "name": "test list"
            })

        with data.policies.fields.lists.policy as {
            "which_fields_forbidden_for_create": []
        }
}

produce_input_doc_by_role(roles, groups, is_email_verified, payload) = test_body if {
    test_body = {
        "httpMethod": "POST",
        "requestPath": "/lists",
        "queryParams": {},
        "encodedJwt": test.produce_token({
            "sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
            "name": "Favorites",
            "admin": true,
            "iat": 1516239022,
            "email_verified": is_email_verified,
            "groups": groups,
            "roles": roles,
        }),
        "requestPayload": payload
    }
}