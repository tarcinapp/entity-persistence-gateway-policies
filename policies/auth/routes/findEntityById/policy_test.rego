package policies.auth.routes.findEntityById.policy

import data.policies.util.common.test as test

test_allow_to_admin {
	allow with input as produce_input(false, ["tarcinapp.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private")

	allow with input as produce_input(false, ["tarcinapp.records.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "protected")

	allow with input as produce_input(false, ["tarcinapp.entities.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "public")

	allow with input as produce_input(false, ["tarcinapp.entities.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private")

	allow with input as produce_input(false, ["tarcinapp.entities.find.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private")

	allow with input as produce_input(false, ["tarcinapp.entities.find.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private")
}

produce_input(verified, roles, groups, ownerUsers, ownerGroups, visibility) = test_body {
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
		"requestPayload": {
			"name": "any-record",
			"ownerUsers": ownerUsers,
			"ownerGroups": ownerGroups,
			"visibility": visibility,
		},
	}
}
