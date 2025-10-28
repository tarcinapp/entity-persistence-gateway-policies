package policies.auth.routes.listsThroughEntity.findListsByEntityId.policy

import data.policies.util.common.test as test

# Admins and editors should be allowed regardless of entity visibility
test_allow_admin if {
    allow with input as produce_input("tarcinapp.admin", true, [], [], [], "private", "2020-01-01T00:00:00Z", null, [], [])
}

test_allow_editor if {
    allow with input as produce_input("tarcinapp.editor", true, [], [], [], "private", "2020-01-01T00:00:00Z", null, [], [])
}

# Member who can find lists but cannot see the entity should be denied
test_not_allow_member_if_cannot_see_entity if {
    not allow with input as produce_input("tarcinapp.member", true, ["other-owner"], [], [], "private", "2020-01-01T00:00:00Z", null, [], [])
}

# Member who is owner and verified can both find lists and see entity
test_allow_member_owner if {
    allow with input as produce_input("tarcinapp.member", true, ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], [], [], "private", "2020-01-01T00:00:00Z", null, [], [])
}

# Member who can see entity but email not verified cannot find lists -> deny
test_not_allow_member_not_verified if {
    not allow with input as produce_input("tarcinapp.member", false, ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], [], [], "private", "2020-01-01T00:00:00Z", null, [], [])
}

# Visitor: allowed only for active public entities
test_allow_visitor_public_active if {
    allow with input as produce_input("tarcinapp.visitor", true, [], [], [], "public", "2020-01-01T00:00:00Z", null, [], [])
}

test_not_allow_visitor_protected if {
    not allow with input as produce_input("tarcinapp.visitor", true, [], [], [], "protected", "2020-01-01T00:00:00Z", null, [], [])
}

# ViewerUsers and ViewerGroups: member in viewerUsers should be allowed for active records
test_allow_member_in_viewerUsers if {
    allow with input as produce_input_with_viewers("tarcinapp.member", true, [], [], [], "private", "2020-01-01T00:00:00Z", null, ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], [])
}

# Member in viewerGroups allowed when record is active and not private
test_allow_member_in_viewerGroups_public if {
    allow with input as produce_input_with_viewers("tarcinapp.member", true, ["users-group-1"], [], [], "public", "2020-01-01T00:00:00Z", null, [], ["users-group-1"])
}

# Helper producers
produce_input(role, is_email_verified, ownerUsers, ownerGroups, visibility_overrides, visibility, validFrom, validUntil, viewerUsers, viewerGroups) = test_body if {
    test_body = {
        "appShortcode": "tarcinapp",
        "httpMethod": "GET",
        "requestPath": "/lists",
        "queryParams": {},
        "encodedJwt": test.produce_token({
            "sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
            "name": "John Doe",
            "admin": true,
            "iat": 1516239022,
            "email_verified": is_email_verified,
            "groups": ["users-group-1"],
            "roles": [
                "offline_access",
                "uma_authorization",
                role,
            ],
        }),
        "appShortcode": "tarcinapp",
        "originalRecord": {
            "name": "any-record",
            "_ownerUsers": ownerUsers,
            "_ownerGroups": ownerGroups,
            "_visibility": visibility,
            "_validFromDateTime": validFrom,
            "_validUntilDateTime": validUntil,
            "_viewerUsers": viewerUsers,
            "_viewerGroups": viewerGroups,
        },
    }
}

produce_input_with_viewers(role, is_email_verified, groups, ownerUsers, ownerGroups, visibility, validFrom, validUntil, viewerUsers, viewerGroups) = test_body if {
    test_body = {
        "appShortcode": "tarcinapp",
        "httpMethod": "GET",
        "requestPath": "/lists",
        "queryParams": {},
        "encodedJwt": test.produce_token({
            "sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
            "name": "John Doe",
            "admin": true,
            "iat": 1516239022,
            "email_verified": is_email_verified,
            "groups": groups,
            "roles": [
                "offline_access",
                "uma_authorization",
                role,
            ],
        }),
        "originalRecord": {
            "name": "any-record",
            "_ownerUsers": ownerUsers,
            "_ownerGroups": ownerGroups,
            "_visibility": visibility,
            "_validFromDateTime": validFrom,
            "_validUntilDateTime": validUntil,
            "_viewerUsers": viewerUsers,
            "_viewerGroups": viewerGroups,
        },
    }
}
