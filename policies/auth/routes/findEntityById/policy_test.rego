package policies.auth.routes.findEntityById.policy

import data.policies.util.common.test as test

test_allow_pendings_to_admin {
	allow with input as produce_input(false, ["tarcinapp.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private", null, null)

	allow with input as produce_input(false, ["tarcinapp.records.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "protected", null, null)

	allow with input as produce_input(false, ["tarcinapp.entities.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "public", null, null)

	allow with input as produce_input(false, ["tarcinapp.entities.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private", null, null)

	allow with input as produce_input(false, ["tarcinapp.entities.find.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private", null, null)

	allow with input as produce_input(false, ["tarcinapp.entities.find.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private", null, null)
}

test_allow_actives_to_admin {
	allow with input as produce_input(false, ["tarcinapp.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private", "2020-01-01T00:00:00Z", null)

	allow with input as produce_input(false, ["tarcinapp.records.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "protected", "2020-01-01T00:00:00Z", null)

	allow with input as produce_input(false, ["tarcinapp.entities.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "public", "2020-01-01T00:00:00Z", null)

	allow with input as produce_input(false, ["tarcinapp.entities.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private", "2020-01-01T00:00:00Z", null)

	allow with input as produce_input(false, ["tarcinapp.entities.find.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private", "2020-01-01T00:00:00Z", null)

	allow with input as produce_input(false, ["tarcinapp.entities.find.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private", "2020-01-01T00:00:00Z", null)
}

test_allow_inactives_to_admin {
	allow with input as produce_input(false, ["tarcinapp.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private", "2020-01-01T00:00:00Z", null)

	allow with input as produce_input(false, ["tarcinapp.records.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "protected", "2020-01-01T00:00:00Z", null)

	allow with input as produce_input(false, ["tarcinapp.entities.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "public", "2020-01-01T00:00:00Z", null)

	allow with input as produce_input(false, ["tarcinapp.entities.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private", "2020-01-01T00:00:00Z", null)

	allow with input as produce_input(false, ["tarcinapp.entities.find.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private", "2020-01-01T00:00:00Z", null)

	allow with input as produce_input(false, ["tarcinapp.entities.find.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private", "2020-01-01T00:00:00Z", null)
}

test_allow_actives_to_editor {
	allow with input as produce_input(false, ["tarcinapp.editor"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private", "2020-01-01T00:00:00Z",  "2020-02-01T00:00:00Z")

	allow with input as produce_input(false, ["tarcinapp.records.editor"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "protected", "2020-01-01T00:00:00Z", "2020-02-01T00:00:00Z")

	allow with input as produce_input(false, ["tarcinapp.entities.editor"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "public", "2020-01-01T00:00:00Z", "2020-02-01T00:00:00Z")

	allow with input as produce_input(false, ["tarcinapp.entities.editor"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private", "2020-01-01T00:00:00Z", "2020-02-01T00:00:00Z")

	allow with input as produce_input(false, ["tarcinapp.entities.find.editor"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private", "2020-01-01T00:00:00Z", "2020-02-01T00:00:00Z")

	allow with input as produce_input(false, ["tarcinapp.entities.find.editor"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private", "2020-01-01T00:00:00Z", "2020-02-01T00:00:00Z")
}

test_allow_actives_to_owner {
    allow with input as produce_input(false, ["tarcinapp.member"], ["users-group-1"], 
        ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        ["any-owner-group-1"],
        "public", 
        "2020-01-01T00:00:00Z", 
        null
    )

    allow with input as produce_input(false, ["tarcinapp.entities.member"], ["users-group-1"], 
        ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        ["any-owner-group-1"],
        "private",
        "2020-01-01T00:00:00Z",
        null
    )

    allow with input as produce_input(false, ["tarcinapp.records.member"], ["users-group-1"], 
        ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        ["any-owner-group-1"],
        "protected",
        "2020-01-01T00:00:00Z",
        null
    )
}

test_allow_pending_to_owner {
	allow with input as produce_input(false, ["tarcinapp.member"], ["users-group-1"], 
        ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        ["any-owner-group-1"],
        "public", 
        null, 
        null
    )

    allow with input as produce_input(false, ["tarcinapp.entities.member"], ["users-group-1"], 
        ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        ["any-owner-group-1"],
        "private",
        null,
        null
    )

    allow with input as produce_input(false, ["tarcinapp.records.member"], ["users-group-1"], 
        ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        ["any-owner-group-1"],
        "protected",
        null,
        null
    )
}

test_not_allow_inactives_to_owner {
	not allow with input as produce_input(false, ["tarcinapp.member"], ["users-group-1"], 
        ["any-owner-user"],
        ["any-owner-group-1"],
        "public",
        "2020-01-01T00:00:00Z",
        "2020-02-01T00:00:00Z",
    )
}

test_allow_pending_to_owner_over_group {
    allow with input as produce_input(false, ["tarcinapp.member"], ["users-group-1"], 
        ["any-owner-user"],
        ["users-group-1"],
        "protected",
        null,
        null
    )
}

test_allow_active_protected_to_owner_over_group {
    allow with input as produce_input(false, ["tarcinapp.member"], ["users-group-1"], 
        ["any-owner-user"],
        ["users-group-1"],
        "protected",
        "2020-01-01T00:00:00Z",
        null
    )
}

test_not_allow_active_private_to_owner_over_group {
    not allow with input as produce_input(false, ["tarcinapp.member"], ["users-group-1"], 
        ["any-owner-user"],
        ["users-group-1"],
        "private",
        "2020-01-01T00:00:00Z",
        null
    )
}

test_allow_active_and_public_to_member {
    allow with input as produce_input(false, ["tarcinapp.member"], ["users-group-1"], 
        ["any-owner-user"],
        ["any-owner-group-1"],
        "public",
        "2020-01-01T00:00:00Z",
        null
    )
}

test_not_allow_active_protected_to_member {
    not allow with input as produce_input(false, ["tarcinapp.member"], ["users-group-1"], 
        ["any-owner-user"],
        ["any-owner-group-1"],
        "protected",
        "2020-01-01T00:00:00Z",
        null
    )
}

test_not_allow_active_private_to_member {
    not allow with input as produce_input(false, ["tarcinapp.member"], ["users-group-1"], 
        ["any-owner-user"],
        ["any-owner-group-1"],
        "private",
        "2020-01-01T00:00:00Z",
        null
    )
}

test_not_allow_inactive_public_to_member {
    not allow with input as produce_input(false, ["tarcinapp.member"], ["users-group-1"], 
        ["any-owner-user"],
        ["any-owner-group-1"],
        "public",
        "2020-01-01T00:00:00Z",
        "2021-01-01T00:00:00Z"
    )
}

produce_input(verified, roles, groups, ownerUsers, ownerGroups, visibility, validFrom, validUntil) = test_body {
	test_body = {
		"httpMethod": "GET",
		"requestPath": "/generic-entities",
		"queryParams": {},
		"encodedJwt": test.produce_token({
			"sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
			"name": "John Doe",
			"admin": true,
			"iat": 1516239022,
			"email_verified": true,
			"groups": groups,
			"roles": roles,
		}),
		"originalRecord": {
			"name": "any-record",
			"ownerUsers": ownerUsers,
			"ownerGroups": ownerGroups,
			"visibility": visibility,
            "validFromDateTime": validFrom,
            "validUntilDateTime": validUntil
		},
	}
}
