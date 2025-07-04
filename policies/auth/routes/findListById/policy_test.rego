package policies.auth.routes.findListById.policy

test_allow_to_admin if {
	allow with input as produce_input_doc_by_role("tarcinapp.admin", true)
}

test_allow_to_editor if {
	allow with input as produce_input_doc_by_role("tarcinapp.editor", true)
}

test_not_allow_to_editor_by_forbidden_field if {
	not allow with input as produce_input_doc_by_role("tarcinapp.editor", true)
}

test_allow_to_member if {
	allow with input as produce_input_doc_by_role("tarcinapp.member", true)
}

test_allow_to_correct_group if {
	allow with input as produce_input_doc_by_role("tarcinapp.member", true)
}

test_not_allow_to_member_email_verification if {
	not allow with input as produce_input_doc_by_role("tarcinapp.member", false)
}

test_not_allow_to_member_by_forbidden_field if {
	not allow with input as produce_input_doc_by_role("tarcinapp.member", true)
}

test_not_allow_to_member_by_invalid_group if {
	not allow with input as produce_input_doc_by_role("tarcinapp.member", true)
}

test_not_allow_to_visitor if {
	not allow with input as produce_input_doc_by_role("tarcinapp.visitor", true)
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

produce_input_doc_by_role(role, is_email_verified) = test_body if {
	test_body = {
		"httpMethod": "GET",
		"requestPath": "/lists/123",
		"queryParams": {},
		"encodedJwt": produce_token({
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
		"requestPayload": {
			"id": "123",
			"name": "test list",
			"visibility": "public",
			"ownerUsers": ["any-owner"],
			"ownerGroups": ["any-owner-group"],
			"validFromDateTime": "2020-01-01T00:00:00Z",
			"validUntilDateTime": null
		}
	}
}

produce_input(is_email_verified, roles, groups, owner_users, owner_groups, visibility, valid_from, valid_until) = test_body if {
	test_body = {
		"httpMethod": "GET",
		"requestPath": "/lists/123",
		"queryParams": {},
		"encodedJwt": produce_token({
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

produce_token(payload) = token if {
	token = io.jwt.encode_sign({"alg": "RS256"}, payload, {
		"kty": "RSA",
		"n": "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
		"e": "AQAB",
		"d": "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",
		"p": "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc",
		"q": "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",
		"dp": "BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",
		"dq": "h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",
		"qi": "IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U",
	})
}
