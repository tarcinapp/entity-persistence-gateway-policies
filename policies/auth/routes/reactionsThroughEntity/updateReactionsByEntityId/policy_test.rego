package policies.auth.routes.reactionsThroughEntity.updateReactionsByEntityId.policy

import data.policies.util.common.test as test

# Helper: build input with a full requestPayload
produce_input_doc_by_role(role, is_email_verified) := test_body if {
	test_body := produce_input_doc_by_role_with_payload(role, is_email_verified, base_payload)
}

produce_input_doc_by_role_with_payload(role, is_email_verified, requestPayload) := test_body if {
	test_body = {
		"appShortcode": "tarcinapp",
		"httpMethod": "PUT",
		"requestPath": "/entities/some-entity-id/reactions",
		"queryParams": {},
		"encodedJwt": test.produce_token({
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
		"requestPayload": requestPayload,
	}
}

# Default request payload
base_payload := {
	"_id": "reaction-1",
	"_entityId": "entity-1",
	"_visibility": "public",
	"_ownerUsers": ["any-owner"],
	"_ownerGroups": ["any-owner-group"],
	"_validFromDateTime": "2020-01-01T00:00:00Z",
	"_validUntilDateTime": null,
}

# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------

test_allow_to_admin if {
	allow with input as produce_input_doc_by_role("tarcinapp.admin", true)
}

test_allow_to_reactions_admin if {
	allow with input as produce_input_doc_by_role("tarcinapp.reactions.admin", true)
}

test_allow_to_entityReactions_admin if {
	allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.admin", true)
}

test_not_allow_to_admin_without_email_verification if {
	not allow with input as produce_input_doc_by_role("tarcinapp.admin", false)
}

# Operation-level admin roles
test_allow_to_reactions_update_admin if {
	allow with input as produce_input_doc_by_role("tarcinapp.reactions.update.admin", true)
}

test_allow_to_entityReactions_update_admin if {
	allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.update.admin", true)
}

test_not_allow_to_reactions_update_admin_without_email_verification if {
	not allow with input as produce_input_doc_by_role("tarcinapp.reactions.update.admin", false)
}

test_not_allow_to_entityReactions_update_admin_without_email_verification if {
	not allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.update.admin", false)
}

# Admin with forbidden fields should be allowed for operation-level admin roles (mirroring lists/entities behavior)

test_allow_to_reactions_update_admin_with_forbidden_fields if {
	forbidden_payload := object.union(base_payload, {
		"_createdDateTime": "2020-01-01T00:00:00Z",
		"_lastUpdatedDateTime": "2020-01-01T00:00:00Z",
	})
	allow with input as produce_input_doc_by_role_with_payload("tarcinapp.reactions.update.admin", true, forbidden_payload)
}

test_allow_to_entityReactions_update_admin_with_forbidden_fields if {
	forbidden_payload := object.union(base_payload, {
		"_createdDateTime": "2020-01-01T00:00:00Z",
		"_lastUpdatedDateTime": "2020-01-01T00:00:00Z",
	})
	allow with input as produce_input_doc_by_role_with_payload("tarcinapp.entityReactions.update.admin", true, forbidden_payload)
}

# ---------------------------------------------------------------------------
# Editor
# ---------------------------------------------------------------------------

test_allow_to_editor if {
	allow with input as produce_input_doc_by_role("tarcinapp.editor", true)
}

test_allow_to_reactions_editor if {
	allow with input as produce_input_doc_by_role("tarcinapp.reactions.editor", true)
}

test_allow_to_entityReactions_editor if {
	allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.editor", true)
}

test_not_allow_to_editor_without_email_verification if {
	not allow with input as produce_input_doc_by_role("tarcinapp.editor", false)
}

# Operation-level editor roles
test_allow_to_reactions_update_editor if {
	allow with input as produce_input_doc_by_role("tarcinapp.reactions.update.editor", true)
}

test_allow_to_entityReactions_update_editor if {
	allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.update.editor", true)
}

test_not_allow_to_reactions_update_editor_without_email_verification if {
	not allow with input as produce_input_doc_by_role("tarcinapp.reactions.update.editor", false)
}

test_not_allow_to_entityReactions_update_editor_without_email_verification if {
	not allow with input as produce_input_doc_by_role("tarcinapp.entityReactions.update.editor", false)
}

# Forbidden field test for editor (should be denied)
test_not_allow_to_editor_with_forbidden_field if {
	forbidden_payload := object.union(base_payload, {"_createdDateTime": "2020-01-01T00:00:00Z"})
	not allow with input as produce_input_doc_by_role_with_payload("tarcinapp.editor", true, forbidden_payload)
}

# Field-level overrides for editor
test_allow_to_editor_with_field_level_permission_for_createdDateTime if {
	custom_payload := object.union(base_payload, {"_createdDateTime": "2020-01-01T00:00:00Z"})
	custom_roles := [
		"offline_access",
		"uma_authorization",
		"tarcinapp.editor",
		"tarcinapp.entityReactions.fields._createdDateTime.update",
	]

	allow with input as {
		"appShortcode": "tarcinapp",
		"httpMethod": "PUT",
		"requestPath": "/entities/some-entity-id/reactions",
		"queryParams": {},
		"encodedJwt": test.produce_token({
			"sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
			"name": "John Doe",
			"admin": true,
			"iat": 1516239022,
			"email_verified": true,
			"groups": ["my-group"],
			"roles": custom_roles,
		}),
		"requestPayload": custom_payload,
	}
}

test_allow_to_editor_with_multiple_field_permissions if {
	custom_payload := object.union(base_payload, {
		"_createdDateTime": "2020-01-01T00:00:00Z",
		"_lastUpdatedDateTime": "2020-01-01T00:00:00Z",
	})
	custom_roles := [
		"offline_access",
		"uma_authorization",
		"tarcinapp.editor",
		"tarcinapp.entityReactions.fields._createdDateTime.update",
		"tarcinapp.entityReactions.fields._lastUpdatedDateTime.update",
	]

	allow with input as {
		"appShortcode": "tarcinapp",
		"httpMethod": "PUT",
		"requestPath": "/entities/some-entity-id/reactions",
		"queryParams": {},
		"encodedJwt": test.produce_token({
			"sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
			"name": "John Doe",
			"admin": true,
			"iat": 1516239022,
			"email_verified": true,
			"groups": ["my-group"],
			"roles": custom_roles,
		}),
		"requestPayload": custom_payload,
	}
}

test_not_allow_to_editor_with_partial_field_permissions if {
	custom_payload := object.union(base_payload, {
		"_createdDateTime": "2020-01-01T00:00:00Z",
		"_lastUpdatedDateTime": "2020-01-01T00:00:00Z",
	})
	custom_roles := [
		"offline_access",
		"uma_authorization",
		"tarcinapp.editor",
		"tarcinapp.entityReactions.fields._createdDateTime.update",
		# Missing permission for _lastUpdatedDateTime
	]

	not allow with input as {
		"appShortcode": "tarcinapp",
		"httpMethod": "PUT",
		"requestPath": "/entities/some-entity-id/reactions",
		"queryParams": {},
		"encodedJwt": test.produce_token({
			"sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
			"name": "John Doe",
			"admin": true,
			"iat": 1516239022,
			"email_verified": true,
			"groups": ["my-group"],
			"roles": custom_roles,
		}),
		"requestPayload": custom_payload,
	}
}

# ---------------------------------------------------------------------------
# Wrong scopes and denied roles
# ---------------------------------------------------------------------------

test_not_allow_to_member if {
	not allow with input as produce_input_doc_by_role("tarcinapp.member", true)
}

test_not_allow_to_visitor if {
	not allow with input as produce_input_doc_by_role("tarcinapp.visitor", true)
}

test_not_allow_to_entities_editor_with_entities_scope if {
	not allow with input as produce_input_doc_by_role("tarcinapp.entities.editor", true)
}

test_not_allow_to_lists_editor_with_lists_scope if {
	not allow with input as produce_input_doc_by_role("tarcinapp.lists.editor", true)
}

test_not_allow_to_records_editor_with_records_scope if {
	not allow with input as produce_input_doc_by_role("tarcinapp.records.editor", true)
}
