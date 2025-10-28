package policies.auth.routes.entitiesThroughList.createEntityByListId.policy

import data.policies.util.common.test as test
import data.policies.util.common.array as array

# End-to-end tests for createEntityByListId policy
# These tests combine createEntity rules (requestPayload) and
# findListById rules (originalRecord visibility). The policy should
# allow only when BOTH creation and list-visibility checks pass.

# ----------------------------
# POSITIVE CASES
# ----------------------------

# Admin should be allowed regardless of list visibility/state
test_allow_to_global_admin if {
    allow with input as produce_input_by_role(["tarcinapp.admin"], true, ["group-1"], {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "public"
    }, {
        "name": "target-list",
        "_ownerUsers": [],
        "_ownerGroups": [],
        "_visibility": "private",
        "_validFromDateTime": null,
        "_validUntilDateTime": null
    })
}

# Editor should be allowed when list is active/public
test_allow_to_global_editor_if_list_public_active if {
    allow with input as produce_input_by_role(["tarcinapp.editor"], true, ["group-1"], {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "public"
    }, {
        "name": "target-list",
        "_ownerUsers": [],
        "_ownerGroups": [],
        "_visibility": "public",
        "_validFromDateTime": "2020-01-01T00:00:00Z",
        "_validUntilDateTime": null
    })
}

# Member can create when list is public and active
test_allow_to_member_when_list_public_active if {
    allow with input as produce_input_by_role(["tarcinapp.member"], true, ["group-1"], {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "public"
    }, {
        "name": "target-list",
        "_ownerUsers": [],
        "_ownerGroups": [],
        "_visibility": "public",
        "_validFromDateTime": "2020-01-01T00:00:00Z",
        "_validUntilDateTime": null
    })
}

# Member who is owner user should be allowed to create under a private list
test_allow_to_member_when_owner_user_and_list_private if {
    allow with input as produce_input_by_role(["tarcinapp.member"], true, ["users-group-1"], {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "public"
    }, {
        "name": "target-list",
        "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        "_ownerGroups": [],
        "_visibility": "private",
        "_validFromDateTime": "2020-01-01T00:00:00Z",
        "_validUntilDateTime": null
    })
}

# Field-level permission allows setting forbidden field and should permit create when other checks pass
test_allow_field_level_permission_allows_forbidden_field if {
    allow with input as produce_input_by_role_with_field_permission(["tarcinapp.member"], true, ["group-1"], {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "public",
        "_createdBy": "some-user"
    }, "tarcinapp.entities.fields._createdBy.create", {
        "name": "target-list",
        "_ownerUsers": [],
        "_ownerGroups": [],
        "_visibility": "public",
        "_validFromDateTime": "2020-01-01T00:00:00Z",
        "_validUntilDateTime": null
    })
}

# ----------------------------
# NEGATIVE CASES
# ----------------------------

# Visitors cannot create even if they can view the list
test_not_allow_visitor_even_if_list_public if {
    not allow with input as produce_input_by_role(["tarcinapp.visitor"], true, ["group-1"], {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "public"
    }, {
        "name": "target-list",
        "_ownerUsers": [],
        "_ownerGroups": [],
        "_visibility": "public",
        "_validFromDateTime": "2020-01-01T00:00:00Z",
        "_validUntilDateTime": null
    })
}

# Member cannot create if list is private and they are not owner
test_not_allow_member_when_list_private_and_not_owner if {
    not allow with input as produce_input_by_role(["tarcinapp.member"], true, ["group-1"], {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "public"
    }, {
        "name": "target-list",
        "_ownerUsers": [],
        "_ownerGroups": ["some-other-group"],
        "_visibility": "private",
        "_validFromDateTime": "2020-01-01T00:00:00Z",
        "_validUntilDateTime": null
    })
}

# Forbidden field without field-level permission should block creation even if list is visible
test_not_allow_forbidden_field_without_permission if {
    not allow with input as produce_input_by_role(["tarcinapp.editor"], true, ["group-1"], {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "public",
        "_createdBy": "some-user"
    }, {
        "name": "target-list",
        "_ownerUsers": [],
        "_ownerGroups": [],
        "_visibility": "public",
        "_validFromDateTime": "2020-01-01T00:00:00Z",
        "_validUntilDateTime": null
    })
}

# Member without email verification should be denied by createEntity rules
test_not_allow_member_without_email_verification if {
    not allow with input as produce_input_by_role(["tarcinapp.member"], false, ["group-1"], {
        "_name": "Test Entity",
        "description": "Test Description",
        "_visibility": "public"
    }, {
        "name": "target-list",
        "_ownerUsers": [],
        "_ownerGroups": [],
        "_visibility": "public",
        "_validFromDateTime": "2020-01-01T00:00:00Z",
        "_validUntilDateTime": null
    })
}

# ----------------------------
# HELPERS
# ----------------------------

produce_input_by_role(roles, is_email_verified, groups, requestPayload, originalRecord) = test_body if {
    test_body = {
        "appShortcode": "tarcinapp",
        "httpMethod": "POST",
        "requestPath": "/lists/some-list/entities",
        "queryParams": {},
        "encodedJwt": test.produce_token({
            "sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
            "name": "John Doe",
            "admin": true,
            "iat": 1516239022,
            "email_verified": is_email_verified,
            "groups": groups,
            "roles": roles,
        }),
        "requestPayload": requestPayload,
        "originalRecord": originalRecord
    }
}

produce_input_by_role_with_field_permission(roles, is_email_verified, groups, requestPayload, fieldPermission, originalRecord) = test_body if {
    # Append field permission into roles list
    combined_roles = array.concat(roles, [fieldPermission])
    test_body = {
        "appShortcode": "tarcinapp",
        "httpMethod": "POST",
        "requestPath": "/lists/some-list/entities",
        "queryParams": {},
        "encodedJwt": test.produce_token({
            "sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
            "name": "John Doe",
            "admin": true,
            "iat": 1516239022,
            "email_verified": is_email_verified,
            "groups": groups,
            "roles": combined_roles,
        }),
        "requestPayload": requestPayload,
        "originalRecord": originalRecord
    }
}
