package policies.auth.routes.entitiesThroughList.updateEntitiesByListId.policy

import data.policies.util.common.test as test

# Tests for updateEntitiesByListId — only admins should be permitted.

produce_input_doc_by_role(roles, is_email_verified) := test_body if {
	test_body = {
		"appShortcode": "tarcinapp",
		"httpMethod": "PUT",
		"requestPath": "/lists/some-list/entities",
		"queryParams": {},
		"encodedJwt": test.produce_token({
			"sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
			"name": "John Doe",
			"admin": true,
			"iat": 1516239022,
			"email_verified": is_email_verified,
			"groups": ["my-group"],
			"roles": roles,
		}),
		"requestPayload": base_payload,
	}
}

produce_input_doc_by_role_with_payload(roles, is_email_verified, requestPayload) := test_body if {
	test_body = {
		"appShortcode": "tarcinapp",
		"httpMethod": "PUT",
		"requestPath": "/lists/some-list/entities",
		"queryParams": {},
		"encodedJwt": test.produce_token({
			"sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
			"name": "John Doe",
			"admin": true,
			"iat": 1516239022,
			"email_verified": is_email_verified,
			"groups": ["my-group"],
			"roles": roles,
		}),
		"requestPayload": requestPayload,
	}
}

# base payload used for updates
base_payload := {
	"_name": "test entity",
	"description": "test description",
	"_visibility": "public",
	"_ownerUsers": ["any-owner"],
	"_ownerGroups": ["any-owner-group"],
	"_validFromDateTime": "2020-01-01T00:00:00Z",
	"_validUntilDateTime": null,
}

test_allow_to_admin if {
	allow with input as produce_input_doc_by_role(["tarcinapp.admin"], true)
	allow with input as produce_input_doc_by_role(["tarcinapp.records.admin"], true)
	allow with input as produce_input_doc_by_role(["tarcinapp.entities.admin"], true)
}

test_not_allow_admin_unverified if {
	not allow with input as produce_input_doc_by_role(["tarcinapp.admin"], false)
	not allow with input as produce_input_doc_by_role(["tarcinapp.records.admin"], false)
}

test_not_allow_editor if {
	not allow with input as produce_input_doc_by_role(["tarcinapp.editor"], true)
	not allow with input as produce_input_doc_by_role(["tarcinapp.records.editor"], true)
	not allow with input as produce_input_doc_by_role(["tarcinapp.entities.editor"], true)
}

test_not_allow_member if {
	not allow with input as produce_input_doc_by_role(["tarcinapp.member"], true)
}

# Forbidden field should block non-admins (editor) even if list scope matches
test_not_allow_editor_with_forbidden_field if {
	forbidden_payload := object.union(base_payload, {"_createdDateTime": "2020-01-01T00:00:00Z"})
	not allow with input as produce_input_doc_by_role_with_payload(["tarcinapp.editor", "tarcinapp.lists.editor"], true, forbidden_payload)
}
