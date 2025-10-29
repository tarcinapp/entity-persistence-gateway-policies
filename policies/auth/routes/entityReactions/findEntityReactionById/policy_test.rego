package policies.auth.routes.entityReactions.findEntityReactionById.policy

import data.policies.util.common.test as test

# Tests for findEntityReactionById
# Follow the structure used in relation/entity tests: provide source and originalRecord
# metadata via helpers that set _validFrom/_validUntil, _visibility, ownership and viewers.

test_allow_admin_when_verified if {
    allow with input as produce_input_doc_by_role("tarcinapp.admin", true,
        {"_id": "entity-1", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
        {"_id": "reaction-1", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []}
    )
}

test_not_allow_admin_without_verified_email if {
    not allow with input as produce_input_doc_by_role("tarcinapp.admin", false,
        {"_id": "entity-1", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
        {"_id": "reaction-1", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []}
    )
}

test_allow_editor_when_verified if {
    allow with input as produce_input_doc_by_role("tarcinapp.editor", true,
        {"_id": "entity-1", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
        {"_id": "reaction-1", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []}
    )
}

test_not_allow_editor_without_verified_email if {
    not allow with input as produce_input_doc_by_role("tarcinapp.editor", false,
        {"_id": "entity-1", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
        {"_id": "reaction-1", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []}
    )
}

# Member: owner of both source and reaction -> allow
test_allow_member_owner_of_both if {
    allow with input as produce_input_doc_by_role("tarcinapp.member", true,
        {"_id": "entity-1", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "protected", "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
        {"_id": "reaction-1", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "protected", "_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []}
    )
}

# Member: source visible but reaction private -> deny
test_not_allow_member_when_reaction_private if {
    not allow with input as produce_input_doc_by_role("tarcinapp.member", true,
        {"_id": "entity-1", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
        {"_id": "reaction-1", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "private", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []}
    )
}

# Visitor: both public & active -> allow
test_allow_visitor_when_both_public_active if {
    allow with input as produce_input_doc_by_role("tarcinapp.visitor", true,
        {"_id": "entity-1", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
        {"_id": "reaction-1", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []}
    )
}

# Missing source -> deny
test_not_allow_missing_source if {
    not allow with input as produce_input_missing_source("tarcinapp.member", true,
        {"_id": "reaction-1", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []}
    )
}

# Missing originalRecord -> deny
test_not_allow_missing_original if {
    not allow with input as produce_input_missing_original("tarcinapp.member", true,
        {"_id": "entity-1", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []}
    )
}

# Edge cases
# Visitor cannot see a reaction that is inactive/expired even if the entity is public
test_not_allow_visitor_if_reaction_expired if {
    not allow with input as produce_input_doc_by_role("tarcinapp.visitor", true,
        {"_id": "entity-1", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
        {"_id": "reaction-1", "_validFromDateTime": "2000-01-01T00:00:00Z", "_validUntilDateTime": "2001-01-01T00:00:00Z", "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []}
    )
}

# Member denied when reaction is pending/protected and they are not owner nor viewer
test_not_allow_member_when_reaction_protected_pending_not_owner if {
    not allow with input as produce_input_doc_by_role("tarcinapp.member", true,
        {"_id": "entity-1", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
        {"_id": "reaction-1", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "protected", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []}
    )
}

# Member allowed if they appear in reaction.viewerUsers
test_allow_member_if_viewer_user_on_reaction if {
    allow with input as produce_input_doc_by_role("tarcinapp.member", true,
        {"_id": "entity-1", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
        {"_id": "reaction-1", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "protected", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], "_viewerGroups": []}
    )
}

# Member allowed if their group is listed in reaction.viewerGroups
test_allow_member_if_viewer_group_on_reaction if {
    allow with input as produce_input_doc_by_role("tarcinapp.member", true,
        {"_id": "entity-1", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
        {"_id": "reaction-1", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "protected", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": ["group-1"]}
    )
}

# Source not active yet (validFrom in future) -> deny
test_not_allow_member_when_source_validFrom_in_future if {
    not allow with input as produce_input_doc_by_role("tarcinapp.member", true,
        {"_id": "entity-1", "_validFromDateTime": "3000-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
        {"_id": "reaction-1", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []}
    )
}

# Source expired (validUntil in past) -> deny even if reaction is active
test_not_allow_member_when_source_expired if {
    not allow with input as produce_input_doc_by_role("tarcinapp.member", true,
        {"_id": "entity-1", "_validFromDateTime": "2000-01-01T00:00:00Z", "_validUntilDateTime": "2001-01-01T00:00:00Z", "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
        {"_id": "reaction-1", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []}
    )
}

# Member allowed if they belong to an ownerGroup listed on the reaction
test_allow_member_if_owner_group_on_reaction if {
    allow with input as produce_input_doc_by_role("tarcinapp.member", true,
        {"_id": "entity-1", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "public", "_ownerUsers": [], "_ownerGroups": [], "_viewerUsers": [], "_viewerGroups": []},
        {"_id": "reaction-1", "_validFromDateTime": "2020-01-01T00:00:00Z", "_validUntilDateTime": null, "_visibility": "protected", "_ownerUsers": [], "_ownerGroups": ["group-1"], "_viewerUsers": [], "_viewerGroups": []}
    )
}

####################
# Helpers (minimal; tests use inline objects)
####################

produce_input_doc_by_role(role, is_email_verified, source, originalRecord) = test_body if {
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
            "groups": ["group-1"],
            "roles": [role]
        }),
        "source": source,
        "originalRecord": originalRecord
    }
}

produce_input_missing_source(role, is_email_verified, originalRecord) = test_body if {
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
            "groups": ["group-1"],
            "roles": [role]
        }),
        "originalRecord": originalRecord
    }
}

produce_input_missing_original(role, is_email_verified, source) = test_body if {
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
            "groups": ["group-1"],
            "roles": [role]
        }),
        "source": source
    }
}


