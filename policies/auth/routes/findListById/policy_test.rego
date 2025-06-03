package policies.auth.routes.findListById.policy

import data.policies.util.common.test as test

test_allow_to_admin if {
	allow with input as test.produce_input_doc_by_role("tarcinapp.admin", true)
}

test_allow_to_editor if {
	allow with input as test.produce_input_doc_by_role("tarcinapp.editor", true)
}

test_not_allow_to_editor_by_forbidden_field if {
	not allow with input as test.produce_input_doc_by_role("tarcinapp.editor", true)
}

test_allow_to_member if {
	allow with input as test.produce_input_doc_by_role("tarcinapp.member", true)
}

test_allow_to_correct_group if {
	allow with input as test.produce_input_doc_by_role("tarcinapp.member", true)
}

test_not_allow_to_member_email_verification if {
	not allow with input as test.produce_input_doc_by_role("tarcinapp.member", false)
}

test_not_allow_to_member_by_forbidden_field if {
	not allow with input as test.produce_input_doc_by_role("tarcinapp.member", true)
}

test_not_allow_to_member_by_invalid_group if {
	not allow with input as test.produce_input_doc_by_role("tarcinapp.member", true)
}

test_not_allow_to_visitor if {
	not allow with input as test.produce_input_doc_by_role("tarcinapp.visitor", true)
}

test_allow_pendings_to_admin if {
	allow with input as produce_input(false, ["tarcinapp.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private", null, null)
	allow with input as produce_input(false, ["tarcinapp.records.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "protected", null, null)
	allow with input as produce_input(false, ["tarcinapp.lists.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "public", null, null)
	allow with input as produce_input(false, ["tarcinapp.lists.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private", null, null)
	allow with input as produce_input(false, ["tarcinapp.lists.find.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private", null, null)
	allow with input as produce_input(false, ["tarcinapp.lists.find.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private", null, null)
}

test_allow_actives_to_admin if {
	allow with input as produce_input(false, ["tarcinapp.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private", "2020-01-01T00:00:00Z", null)
	allow with input as produce_input(false, ["tarcinapp.records.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "protected", "2020-01-01T00:00:00Z", null)
	allow with input as produce_input(false, ["tarcinapp.lists.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "public", "2020-01-01T00:00:00Z", null)
	allow with input as produce_input(false, ["tarcinapp.lists.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private", "2020-01-01T00:00:00Z", null)
	allow with input as produce_input(false, ["tarcinapp.lists.find.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private", "2020-01-01T00:00:00Z", null)
	allow with input as produce_input(false, ["tarcinapp.lists.find.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private", "2020-01-01T00:00:00Z", null)
}

test_allow_inactives_to_admin if {
	allow with input as produce_input(false, ["tarcinapp.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private", "2020-01-01T00:00:00Z", null)
	allow with input as produce_input(false, ["tarcinapp.records.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "protected", "2020-01-01T00:00:00Z", null)
	allow with input as produce_input(false, ["tarcinapp.lists.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "public", "2020-01-01T00:00:00Z", null)
	allow with input as produce_input(false, ["tarcinapp.lists.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private", "2020-01-01T00:00:00Z", null)
	allow with input as produce_input(false, ["tarcinapp.lists.find.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private", "2020-01-01T00:00:00Z", null)
	allow with input as produce_input(false, ["tarcinapp.lists.find.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private", "2020-01-01T00:00:00Z", null)
}

test_allow_actives_to_editor if {
	allow with input as produce_input(false, ["tarcinapp.editor"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private", "2020-01-01T00:00:00Z", "2020-02-01T00:00:00Z")
	allow with input as produce_input(false, ["tarcinapp.records.editor"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "protected", "2020-01-01T00:00:00Z", "2020-02-01T00:00:00Z")
	allow with input as produce_input(false, ["tarcinapp.lists.editor"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "public", "2020-01-01T00:00:00Z", "2020-02-01T00:00:00Z")
	allow with input as produce_input(false, ["tarcinapp.lists.editor"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private", "2020-01-01T00:00:00Z", "2020-02-01T00:00:00Z")
	allow with input as produce_input(false, ["tarcinapp.lists.find.editor"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private", "2020-01-01T00:00:00Z", "2020-02-01T00:00:00Z")
	allow with input as produce_input(false, ["tarcinapp.lists.find.editor"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private", "2020-01-01T00:00:00Z", "2020-02-01T00:00:00Z")
}

test_allow_actives_to_owner if {
	allow with input as produce_input(false, ["tarcinapp.member"], ["users-group-1"], ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], ["any-owner-group-1"], "public", "2020-01-01T00:00:00Z", null)
	allow with input as produce_input(false, ["tarcinapp.lists.member"], ["users-group-1"], ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], ["any-owner-group-1"], "private", "2020-01-01T00:00:00Z", null)
	allow with input as produce_input(false, ["tarcinapp.records.member"], ["users-group-1"], ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], ["any-owner-group-1"], "protected", "2020-01-01T00:00:00Z", null)
}

test_allow_pending_to_owner if {
	allow with input as produce_input(false, ["tarcinapp.member"], ["users-group-1"], ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], ["any-owner-group-1"], "public", null, null)
	allow with input as produce_input(false, ["tarcinapp.lists.member"], ["users-group-1"], ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], ["any-owner-group-1"], "private", null, null)
	allow with input as produce_input(false, ["tarcinapp.records.member"], ["users-group-1"], ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], ["any-owner-group-1"], "protected", null, null)
}

test_not_allow_inactives_to_owner if {
	not allow with input as produce_input(false, ["tarcinapp.member"], ["users-group-1"], ["any-owner-user"], ["any-owner-group-1"], "public", "2020-01-01T00:00:00Z", "2020-02-01T00:00:00Z")
}

test_allow_pending_to_owner_over_group if {
	allow with input as produce_input(false, ["tarcinapp.member"], ["users-group-1"], ["any-owner-user"], ["users-group-1"], "protected", null, null)
}

test_allow_active_protected_to_owner_over_group if {
	allow with input as produce_input(false, ["tarcinapp.member"], ["users-group-1"], ["any-owner-user"], ["users-group-1"], "protected", "2020-01-01T00:00:00Z", null)
}

test_not_allow_active_private_to_owner_over_group if {
	not allow with input as produce_input(false, ["tarcinapp.member"], ["users-group-1"], ["any-owner-user"], ["users-group-1"], "private", "2020-01-01T00:00:00Z", null)
}

test_allow_active_and_public_to_member if {
	allow with input as produce_input(false, ["tarcinapp.member"], ["users-group-1"], ["any-owner-user"], ["any-owner-group-1"], "public", "2020-01-01T00:00:00Z", null)
}

test_not_allow_active_protected_to_member if {
	not allow with input as produce_input(false, ["tarcinapp.member"], ["users-group-1"], ["any-owner-user"], ["any-owner-group-1"], "protected", "2020-01-01T00:00:00Z", null)
}

test_not_allow_active_private_to_member if {
	not allow with input as produce_input(false, ["tarcinapp.member"], ["users-group-1"], ["any-owner-user"], ["any-owner-group-1"], "private", "2020-01-01T00:00:00Z", null)
}

test_not_allow_inactive_public_to_member if {
	not allow with input as produce_input(false, ["tarcinapp.member"], ["users-group-1"], ["any-owner-user"], ["any-owner-group-1"], "public", "2020-01-01T00:00:00Z", "2021-01-01T00:00:00Z")
}

produce_input(is_email_verified, roles, groups, owner_users, owner_groups, visibility, valid_from, valid_until) = test_body if {
	test_body = {
		"httpMethod": "GET",
		"requestPath": "/lists/123",
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
		"requestPayload": {
			"id": "123",
			"name": "test list",
			"visibility": visibility,
			"ownerUsers": owner_users,
			"ownerGroups": owner_groups,
			"validFromDateTime": valid_from,
			"validUntilDateTime": valid_until
		}
	}
}
