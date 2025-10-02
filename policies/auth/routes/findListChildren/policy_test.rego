package policies.auth.routes.findListChildren.policy

import data.policies.util.common.test as test

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
	allow with input as produce_input(false, ["tarcinapp.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private", "2020-01-01T00:00:00Z", "2021-01-01T00:00:00Z")
	allow with input as produce_input(false, ["tarcinapp.records.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "protected", "2020-01-01T00:00:00Z", "2021-01-01T00:00:00Z")
	allow with input as produce_input(false, ["tarcinapp.lists.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "public", "2020-01-01T00:00:00Z", "2021-01-01T00:00:00Z")
	allow with input as produce_input(false, ["tarcinapp.lists.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private", "2020-01-01T00:00:00Z", "2021-01-01T00:00:00Z")
	allow with input as produce_input(false, ["tarcinapp.lists.find.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private", "2020-01-01T00:00:00Z", "2021-01-01T00:00:00Z")
	allow with input as produce_input(false, ["tarcinapp.lists.find.admin"], ["any-group-1"], ["any-owner"], ["any-owner-group-1"], "private", "2020-01-01T00:00:00Z", "2021-01-01T00:00:00Z")
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

# Test cases for viewerUsers scenarios
test_allow_active_record_with_user_in_viewerUsers if {
	allow with input as produce_input_with_viewerUsers(false, ["tarcinapp.member"], ["users-group-1"], ["any-owner-user"], ["any-owner-group-1"], "private", "2020-01-01T00:00:00Z", null, ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], [])
}

test_not_allow_inactive_record_with_user_in_viewerUsers if {
	not allow with input as produce_input_with_viewerUsers(false, ["tarcinapp.member"], ["users-group-1"], ["any-owner-user"], ["any-owner-group-1"], "private", "2020-01-01T00:00:00Z", "2021-01-01T00:00:00Z", ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], [])
}

test_not_allow_record_with_user_not_in_viewerUsers if {
	not allow with input as produce_input_with_viewerUsers(false, ["tarcinapp.member"], ["users-group-1"], ["any-owner-user"], ["any-owner-group-1"], "private", "2020-01-01T00:00:00Z", null, ["different-user-id"], [])
}

# Test cases for viewerGroups scenarios
test_allow_active_protected_record_with_user_group_in_viewerGroups if {
	allow with input as produce_input_with_viewerGroups(false, ["tarcinapp.member"], ["users-group-1"], ["any-owner-user"], ["any-owner-group-1"], "protected", "2020-01-01T00:00:00Z", null, [], ["users-group-1"])
}

test_allow_active_public_record_with_user_group_in_viewerGroups if {
	allow with input as produce_input_with_viewerGroups(false, ["tarcinapp.member"], ["users-group-1"], ["any-owner-user"], ["any-owner-group-1"], "public", "2020-01-01T00:00:00Z", null, [], ["users-group-1"])
}

test_not_allow_active_private_record_with_user_group_in_viewerGroups if {
	not allow with input as produce_input_with_viewerGroups(false, ["tarcinapp.member"], ["users-group-1"], ["any-owner-user"], ["any-owner-group-1"], "private", "2020-01-01T00:00:00Z", null, [], ["users-group-1"])
}

test_not_allow_inactive_record_with_user_group_in_viewerGroups if {
	not allow with input as produce_input_with_viewerGroups(false, ["tarcinapp.member"], ["users-group-1"], ["any-owner-user"], ["any-owner-group-1"], "protected", "2020-01-01T00:00:00Z", "2021-01-01T00:00:00Z", [], ["users-group-1"])
}

test_not_allow_record_with_user_group_not_in_viewerGroups if {
	not allow with input as produce_input_with_viewerGroups(false, ["tarcinapp.member"], ["users-group-1"], ["any-owner-user"], ["any-owner-group-1"], "protected", "2020-01-01T00:00:00Z", null, [], ["different-group"])
}

# Additional edge cases for complete coverage
test_not_allow_pending_record_with_user_in_viewerUsers if {
	not allow with input as produce_input_with_viewerUsers(false, ["tarcinapp.member"], ["users-group-1"], ["any-owner-user"], ["any-owner-group-1"], "private", null, null, ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], [])
}

test_not_allow_pending_record_with_user_group_in_viewerGroups if {
	not allow with input as produce_input_with_viewerGroups(false, ["tarcinapp.member"], ["users-group-1"], ["any-owner-user"], ["any-owner-group-1"], "protected", null, null, [], ["users-group-1"])
}

test_not_allow_pending_private_record_with_user_group_in_viewerGroups if {
	not allow with input as produce_input_with_viewerGroups(false, ["tarcinapp.member"], ["users-group-1"], ["any-owner-user"], ["any-owner-group-1"], "private", null, null, [], ["users-group-1"])
}

# Test visitor role restrictions
test_allow_active_public_to_visitor if {
	allow with input as produce_input(false, ["tarcinapp.visitor"], ["users-group-1"], ["any-owner-user"], ["any-owner-group-1"], "public", "2020-01-01T00:00:00Z", null)
}

test_not_allow_active_protected_to_visitor if {
	not allow with input as produce_input(false, ["tarcinapp.visitor"], ["users-group-1"], ["any-owner-user"], ["any-owner-group-1"], "protected", "2020-01-01T00:00:00Z", null)
}

test_not_allow_active_private_to_visitor if {
	not allow with input as produce_input(false, ["tarcinapp.visitor"], ["users-group-1"], ["any-owner-user"], ["any-owner-group-1"], "private", "2020-01-01T00:00:00Z", null)
}

test_not_allow_inactive_public_to_visitor if {
	not allow with input as produce_input(false, ["tarcinapp.visitor"], ["users-group-1"], ["any-owner-user"], ["any-owner-group-1"], "public", "2020-01-01T00:00:00Z", "2021-01-01T00:00:00Z")
}

test_not_allow_pending_public_to_visitor if {
	not allow with input as produce_input(false, ["tarcinapp.visitor"], ["users-group-1"], ["any-owner-user"], ["any-owner-group-1"], "public", null, null)
}

produce_input(verified, roles, groups, ownerUsers, ownerGroups, visibility, validFrom, validUntil) = test_body if {
	test_body = {
		"appShortcode": "tarcinapp",
		"httpMethod": "GET",
		"requestPath": "/lists/456/children",
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
			"_id": "456",
			"name": "Parent List",
			"_ownerUsers": ownerUsers,
			"_ownerGroups": ownerGroups,
			"_visibility": visibility,
            "_validFromDateTime": validFrom,
            "_validUntilDateTime": validUntil
		},
	}
}

produce_input_with_viewerUsers(verified, roles, groups, ownerUsers, ownerGroups, visibility, validFrom, validUntil, viewerUsers, viewerGroups) = test_body if {
	test_body = {
		"appShortcode": "tarcinapp",
		"httpMethod": "GET",
		"requestPath": "/lists/456/children",
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
			"_id": "456",
			"name": "Parent List",
			"_ownerUsers": ownerUsers,
			"_ownerGroups": ownerGroups,
			"_visibility": visibility,
            "_validFromDateTime": validFrom,
            "_validUntilDateTime": validUntil,
            "_viewerUsers": viewerUsers,
            "_viewerGroups": viewerGroups
		},
	}
}

produce_input_with_viewerGroups(verified, roles, groups, ownerUsers, ownerGroups, visibility, validFrom, validUntil, viewerUsers, viewerGroups) = test_body if {
	test_body = {
		"appShortcode": "tarcinapp",
		"httpMethod": "GET",
		"requestPath": "/lists/456/children",
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
			"_id": "456",
			"name": "Parent List",
			"_ownerUsers": ownerUsers,
			"_ownerGroups": ownerGroups,
			"_visibility": visibility,
            "_validFromDateTime": validFrom,
            "_validUntilDateTime": validUntil,
            "_viewerUsers": viewerUsers,
            "_viewerGroups": viewerGroups
		},
	}
}