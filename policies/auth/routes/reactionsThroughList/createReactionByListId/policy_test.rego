package policies.auth.routes.reactionsThroughList.createReactionByListId.policy

import data.policies.util.common.test as test

# Combined tests for createReactionByListId: role-based creation + source visibility

# Admin and editor should be allowed to create reactions regardless of source visibility
test_allow_admin_create_reaction if {
	allow with input as produce_input_doc_by_role_and_source("tarcinapp.admin", true, {"type": "like"}, "private", "2020-01-01T00:00:00Z", null)
}

test_allow_editor_create_reaction if {
	allow with input as produce_input_doc_by_role_and_source("tarcinapp.editor", true, {"type": "like"}, "protected", "2020-01-01T00:00:00Z", null)
}

# Members allowed only if they can see the source (based on findListById rules)
test_allow_member_when_source_public_active if {
	allow with input as produce_input_doc_by_role_and_source("tarcinapp.member", true, {"type": "love"}, "public", "2020-01-01T00:00:00Z", null)
}

test_not_allow_member_when_source_protected_not_member if {
	not allow with input as produce_input_doc_by_role_and_source("tarcinapp.member", true, {"type": "love"}, "protected", "2020-01-01T00:00:00Z", null)
}

# Member who is direct owner can react to pending or active but not passive
test_not_allow_member_owner_pending if {
	not allow with input as produce_input_doc_by_role_and_source_with_owner("tarcinapp.member", true, {"type": "haha"}, "private", null, null, ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], [])
}

test_not_allow_member_owner_inactive_passive if {
	not allow with input as produce_input_doc_by_role_and_source_with_owner("tarcinapp.member", true, {"type": "haha"}, "public", "2020-01-01T00:00:00Z", "2021-01-01T00:00:00Z", ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"], [])
}

# Visitors must NOT be allowed to create reactions even if source is public
test_not_allow_visitor_even_if_source_public_active if {
	not allow with input as produce_input_doc_by_role_and_source("tarcinapp.visitor", true, {"type": "like"}, "public", "2020-01-01T00:00:00Z", null)
}

# Member _ownerGroups validations (payload-level) — group membership checked against token
test_allow_member_with_ownerGroups_valid if {
	allow with input as produce_input_doc_by_role_and_source_with_payload_groups("tarcinapp.member", true, {"type": "wow", "_ownerGroups": ["group-1"]}, "public", "2020-01-01T00:00:00Z", null)
}

test_not_allow_member_with_ownerGroups_invalid if {
	not allow with input as produce_input_doc_by_role_and_source_with_payload_groups("tarcinapp.member", true, {"type": "wow", "_ownerGroups": ["group-2"]}, "public", "2020-01-01T00:00:00Z", null)
}

## Helpers
produce_input_doc_by_role_and_source(roles, is_email_verified, requestPayload, visibility, validFrom, validUntil) := test_body if {
	test_body = {
		"appShortcode": "tarcinapp",
		"httpMethod": "POST",
		"requestPath": "/lists/some-list-id/reactions",
		"queryParams": {},
		"encodedJwt": test.produce_token({
			"sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
			"name": "John Doe",
			"admin": true,
			"iat": 1516239022,
			"email_verified": is_email_verified,
			"groups": ["group-1", "group-3"],
			"roles": [roles],
		}),
		"requestPayload": object.union(requestPayload, {"_relationMetadata": {
			"name": "some-list",
			"_ownerUsers": ["any-owner-user"],
			"_ownerGroups": ["any-owner-group-1"],
			"_visibility": visibility,
			"_validFromDateTime": validFrom,
			"_validUntilDateTime": validUntil,
		}}),
	}
}

produce_input_doc_by_role_and_source_with_owner(roles, is_email_verified, requestPayload, visibility, validFrom, validUntil, ownerUsers, ownerGroups) := test_body if {
	test_body = {
		"appShortcode": "tarcinapp",
		"httpMethod": "POST",
		"requestPath": "/lists/some-list-id/reactions",
		"queryParams": {},
		"encodedJwt": test.produce_token({
			"sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
			"name": "John Doe",
			"admin": true,
			"iat": 1516239022,
			"email_verified": is_email_verified,
			"groups": ["users-group-1"],
			"roles": [roles],
		}),
		"requestPayload": object.union(requestPayload, {"_relationMetadata": {
			"name": "some-list",
			"_ownerUsers": ownerUsers,
			"_ownerGroups": ownerGroups,
			"_visibility": visibility,
			"_validFromDateTime": validFrom,
			"_validUntilDateTime": validUntil,
		}}),
	}
}

produce_input_doc_by_role_and_source_with_payload_groups(roles, is_email_verified, requestPayload, visibility, validFrom, validUntil) := test_body if {
	test_body = {
		"appShortcode": "tarcinapp",
		"httpMethod": "POST",
		"requestPath": "/lists/some-list-id/reactions",
		"queryParams": {},
		"encodedJwt": test.produce_token({
			"sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
			"name": "John Doe",
			"admin": true,
			"iat": 1516239022,
			"email_verified": is_email_verified,
			"groups": ["group-1", "group-3"],
			"roles": [roles],
		}),
		"requestPayload": object.union(requestPayload, {"_relationMetadata": {
			"name": "some-list",
			"_ownerUsers": ["any-owner-user"],
			"_ownerGroups": ["any-owner-group-1"],
			"_visibility": visibility,
			"_validFromDateTime": validFrom,
			"_validUntilDateTime": validUntil,
		}}),
	}
}
