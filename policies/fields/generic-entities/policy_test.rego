package policies.fields.genericentities.policy

# This test checks if we can receive desired list of fields for given roles.
# Roles are given from the most upper level like tarcinapp.{rolename}
test_which_fields_forbidden_for_finding_admin if {
	which_fields_forbidden_for_finding = []
}

test_which_fields_forbidden_for_finding_editor if {
	which_fields_forbidden_for_finding = []
}

test_which_fields_forbidden_for_finding_member if {
	which_fields_forbidden_for_finding = []
}

test_which_fields_forbidden_for_finding_visitor if {
	which_fields_forbidden_for_finding = []
}

test_which_fields_forbidden_for_create_admin if {
	which_fields_forbidden_for_create = []
}

test_which_fields_forbidden_for_create_editor if {
	which_fields_forbidden_for_create = []
}

test_which_fields_forbidden_for_create_member if {
	which_fields_forbidden_for_create = []
}

test_which_fields_forbidden_for_create_visitor if {
	which_fields_forbidden_for_create = []
}

test_which_fields_forbidden_for_update_admin if {
	which_fields_forbidden_for_update = []
}

test_which_fields_forbidden_for_update_editor if {
	which_fields_forbidden_for_update = []
}

test_which_fields_forbidden_for_update_member if {
	which_fields_forbidden_for_update = []
}

test_which_fields_forbidden_for_update_visitor if {
	which_fields_forbidden_for_update = []
}

test_get_fields_for if {
	get_fields_for("admin", "find") = []
}

test_get_effective_fields_for if {
	get_effective_fields_for("admin", "find") = []
}

test_can_user_find_field if {
	can_user_find_field("name")
}

test_can_user_create_field if {
	can_user_create_field("name")
}

test_can_user_update_field if {
	can_user_update_field("name")
}

test_admin_find if {
	which_fields_forbidden_for_finding = [] with input as produce_input_doc_by_role(["tarcinapp.admin"])
}

test_admin_create if {
	which_fields_forbidden_for_create = [] with input as produce_input_doc_by_role(["tarcinapp.admin"])
}

test_admin_update if {
	which_fields_forbidden_for_update = [] with input as produce_input_doc_by_role(["tarcinapp.admin"])
}

test_editor_find if {
	which_fields_forbidden_for_finding = [] with input as produce_input_doc_by_role(["tarcinapp.editor"])
}

test_editor_create if {
	which_fields_forbidden_for_create = ["creationDateTime", "lastUpdatedDateTime", "lastUpdatedBy", "createdBy"] with input as produce_input_doc_by_role(["tarcinapp.editor"])
}

test_editor_update if {
	which_fields_forbidden_for_update = ["creationDateTime", "lastUpdatedDateTime", "lastUpdatedBy", "createdBy"] with input as produce_input_doc_by_role(["tarcinapp.editor"])
}

test_member_find if {
	which_fields_forbidden_for_finding = ["visibility"] with input as produce_input_doc_by_role(["tarcinapp.member"])
}

test_member_create if {
	which_fields_forbidden_for_create = ["visibility", "creationDateTime", "lastUpdatedDateTime", "lastUpdatedBy", "createdBy", "validFromDateTime", "validUntilDateTime", "ownerUsers"] with input as produce_input_doc_by_role(["tarcinapp.member"])
}

test_member_update if {
	which_fields_forbidden_for_update = ["visibility", "kind", "creationDateTime", "lastUpdatedDateTime", "lastUpdatedBy", "createdBy", "validFromDateTime", "validUntilDateTime"] with input as produce_input_doc_by_role(["tarcinapp.member"])
}

test_visitor_find if {
	which_fields_forbidden_for_finding = ["validFromDateTime", "validUntilDateTime", "visibility", "lastUpdatedBy", "lastUpdatedDateTime"] with input as produce_input_doc_by_role(["tarcinapp.visitor"])
}

test_editor_creationDateTime_create if {
	which_fields_forbidden_for_create = ["lastUpdatedDateTime", "lastUpdatedBy", "createdBy"] with input as produce_input_doc_by_role(["tarcinapp.editor", "tarcinapp.records.fields.creationDateTime.manage"])
	which_fields_forbidden_for_create = ["lastUpdatedDateTime", "lastUpdatedBy", "createdBy"] with input as produce_input_doc_by_role(["tarcinapp.editor", "tarcinapp.records.fields.creationDateTime.create"])
	which_fields_forbidden_for_create = ["lastUpdatedDateTime", "lastUpdatedBy", "createdBy"] with input as produce_input_doc_by_role(["tarcinapp.editor", "tarcinapp.entities.fields.creationDateTime.manage"])
	which_fields_forbidden_for_create = ["lastUpdatedDateTime", "lastUpdatedBy", "createdBy"] with input as produce_input_doc_by_role(["tarcinapp.editor", "tarcinapp.entities.fields.creationDateTime.create"])
	which_fields_forbidden_for_create = ["creationDateTime", "lastUpdatedDateTime", "lastUpdatedBy", "createdBy"] with input as produce_input_doc_by_role(["tarcinapp.editor", "tarcinapp.entities.fields.creationDateTime.find"])
	which_fields_forbidden_for_create = ["creationDateTime", "lastUpdatedDateTime", "lastUpdatedBy", "createdBy"] with input as produce_input_doc_by_role(["tarcinapp.editor", "tarcinapp.entities.fields.visibility.create"])
}

produce_input_doc_by_role(roles) = test_body if {
	test_body = {
		"httpMethod": "GET",
		"requestPath": "/generic-entities/123",
		"queryParams": {},
		"encodedJwt": produce_token({
			"sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
			"name": "John Doe",
			"admin": true,
			"iat": 1516239022,
			"email_verified": true,
			"groups": ["my-group"],
			"roles": roles,
		}),
		"requestPayload": {
			"id": "123",
			"name": "test entity",
			"description": "test description",
			"creationDateTime": "2020-01-01T00:00:00Z",
			"lastUpdatedDateTime": "2020-01-02T00:00:00Z",
			"lastUpdatedBy": "user-1",
			"createdBy": "user-1",
			"visibility": "public",
			"ownerUsers": ["any-owner"],
			"ownerGroups": ["any-owner-group"],
			"validFromDateTime": "2020-01-01T00:00:00Z",
			"validUntilDateTime": null
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
