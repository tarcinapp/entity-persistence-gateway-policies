package policies.auth.routes.relations.findRelationById.policy

import data.policies.util.common.test as test

# Tests for findRelationById policy
# Covers admin/editor/member/visitor baselines, member positive/negative cases and edge cases

# ========================================
# BASELINE ROLE / EMAIL VERIFICATION TESTS
# ========================================

# Admin: email verified -> allow
test_allow_admin_with_verified_email if {
	allow with input as produce_input_doc_by_role("tarcinapp.admin", true, {
		"_fromMetadata": {"_id": "list-1","_validFromDateTime": "2020-01-01T00:00:00Z","_validUntilDateTime": null,"_visibility": "private","_ownerUsers": [],"_ownerGroups": [],"_viewerUsers": [],"_viewerGroups": []},
		"_toMetadata":   {"_id": "entity-1","_validFromDateTime": "2020-01-01T00:00:00Z","_validUntilDateTime": null,"_visibility": "public","_ownerUsers": [],"_ownerGroups": [],"_viewerUsers": [],"_viewerGroups": []}
	})
}

# Admin: not email verified -> deny
test_not_allow_admin_without_verified_email if {
	not allow with input as produce_input_doc_by_role("tarcinapp.admin", false, {
		"_fromMetadata": {"_id": "list-1","_validFromDateTime": "2020-01-01T00:00:00Z","_validUntilDateTime": null,"_visibility": "private","_ownerUsers": [],"_ownerGroups": [],"_viewerUsers": [],"_viewerGroups": []},
		"_toMetadata":   {"_id": "entity-1","_validFromDateTime": "2020-01-01T00:00:00Z","_validUntilDateTime": null,"_visibility": "public","_ownerUsers": [],"_ownerGroups": [],"_viewerUsers": [],"_viewerGroups": []}
	})
}

# Editor: verified -> allow
test_allow_editor_with_verified_email if {
	allow with input as produce_input_doc_by_role("tarcinapp.editor", true, {
		"_fromMetadata": {"_id": "list-1","_validFromDateTime": null,"_validUntilDateTime": null,"_visibility": "private","_ownerUsers": [],"_ownerGroups": [],"_viewerUsers": [],"_viewerGroups": []},
		"_toMetadata":   {"_id": "entity-1","_validFromDateTime": "2020-01-01T00:00:00Z","_validUntilDateTime": null,"_visibility": "private","_ownerUsers": [],"_ownerGroups": [],"_viewerUsers": [],"_viewerGroups": []}
	})
}

# Editor: not verified -> deny
test_not_allow_editor_without_verified_email if {
	not allow with input as produce_input_doc_by_role("tarcinapp.editor", false, {
		"_fromMetadata": {"_id": "list-1","_validFromDateTime": null,"_validUntilDateTime": null,"_visibility": "private","_ownerUsers": [],"_ownerGroups": [],"_viewerUsers": [],"_viewerGroups": []},
		"_toMetadata":   {"_id": "entity-1","_validFromDateTime": "2020-01-01T00:00:00Z","_validUntilDateTime": null,"_visibility": "private","_ownerUsers": [],"_ownerGroups": [],"_viewerUsers": [],"_viewerGroups": []}
	})
}

# Member: verified and able to see both -> allow (baseline)
test_allow_member_with_verified_email_if_can_see_both if {
	allow with input as produce_input_doc_by_role("tarcinapp.member", true, {
		"_fromMetadata": {"_id": "list-1","_validFromDateTime": "2020-01-01T00:00:00Z","_validUntilDateTime": null,"_visibility": "public","_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],"_ownerGroups": [],"_viewerUsers": [],"_viewerGroups": []},
		"_toMetadata":   {"_id": "entity-1","_validFromDateTime": "2020-01-01T00:00:00Z","_validUntilDateTime": null,"_visibility": "public","_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],"_ownerGroups": [],"_viewerUsers": [],"_viewerGroups": []}
	})
}

# Member: not verified -> deny
test_not_allow_member_without_verified_email if {
	not allow with input as produce_input_doc_by_role("tarcinapp.member", false, {
		"_fromMetadata": {"_id": "list-1","_validFromDateTime": "2020-01-01T00:00:00Z","_validUntilDateTime": null,"_visibility": "public","_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],"_ownerGroups": [],"_viewerUsers": [],"_viewerGroups": []},
		"_toMetadata":   {"_id": "entity-1","_validFromDateTime": "2020-01-01T00:00:00Z","_validUntilDateTime": null,"_visibility": "public","_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],"_ownerGroups": [],"_viewerUsers": [],"_viewerGroups": []}
	})
}

# Visitor: both public & active and verified -> allow
test_allow_visitor_when_both_public_and_active_if_verified if {
	allow with input as produce_input_doc_by_role("tarcinapp.visitor", true, {
		"_fromMetadata": {"_id": "list-1","_validFromDateTime": "2020-01-01T00:00:00Z","_validUntilDateTime": null,"_visibility": "public","_ownerUsers": [],"_ownerGroups": [],"_viewerUsers": [],"_viewerGroups": []},
		"_toMetadata":   {"_id": "entity-1","_validFromDateTime": "2020-01-01T00:00:00Z","_validUntilDateTime": null,"_visibility": "public","_ownerUsers": [],"_ownerGroups": [],"_viewerUsers": [],"_viewerGroups": []}
	})
}

# Visitor: same public/active but not verified -> deny
test_not_allow_visitor_without_verified_email if {
	not allow with input as produce_input_doc_by_role("tarcinapp.visitor", false, {
		"_fromMetadata": {"_id": "list-1","_validFromDateTime": "2020-01-01T00:00:00Z","_validUntilDateTime": null,"_visibility": "public","_ownerUsers": [],"_ownerGroups": [],"_viewerUsers": [],"_viewerGroups": []},
		"_toMetadata":   {"_id": "entity-1","_validFromDateTime": "2020-01-01T00:00:00Z","_validUntilDateTime": null,"_visibility": "public","_ownerUsers": [],"_ownerGroups": [],"_viewerUsers": [],"_viewerGroups": []}
	})
}

# ========================================
# MEMBER POSITIVE TESTS (visibility combinations)
# ========================================

# Member: direct owner of both source and target
test_allow_member_when_direct_owner_of_source_and_target if {
	allow with input as produce_input_doc_by_role("tarcinapp.member", true, {
		"_fromMetadata": {"_id": "list-1","_validFromDateTime": "2020-01-01T00:00:00Z","_validUntilDateTime": null,"_visibility": "protected","_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],"_ownerGroups": [],"_viewerUsers": [],"_viewerGroups": []},
		"_toMetadata":   {"_id": "entity-1","_validFromDateTime": "2020-01-01T00:00:00Z","_validUntilDateTime": null,"_visibility": "protected","_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],"_ownerGroups": [],"_viewerUsers": [],"_viewerGroups": []}
	})
}

# Member: ownerGroups membership permits access for source and/or target
test_allow_member_when_ownerGroups_match_and_visibility_allows if {
	allow with input as produce_input_doc_by_role("tarcinapp.member", true, {
		"_fromMetadata": {"_id": "list-1","_validFromDateTime": "2020-01-01T00:00:00Z","_validUntilDateTime": null,"_visibility": "protected","_ownerUsers": [],"_ownerGroups": ["group-1"],"_viewerUsers": [],"_viewerGroups": []},
		"_toMetadata":   {"_id": "entity-1","_validFromDateTime": "2020-01-01T00:00:00Z","_validUntilDateTime": null,"_visibility": "protected","_ownerUsers": [],"_ownerGroups": ["group-1"],"_viewerUsers": [],"_viewerGroups": []}
	})
}

# Member: target allows access via viewerUsers
test_allow_member_when_target_has_viewer_user if {
	allow with input as produce_input_doc_by_role("tarcinapp.member", true, {
		"_fromMetadata": {"_id": "list-1","_validFromDateTime": "2020-01-01T00:00:00Z","_validUntilDateTime": null,"_visibility": "public","_ownerUsers": [],"_ownerGroups": [],"_viewerUsers": [],"_viewerGroups": []},
		"_toMetadata":   {"_id": "entity-1","_validFromDateTime": "2020-01-01T00:00:00Z","_validUntilDateTime": null,"_visibility": "protected","_ownerUsers": [],"_ownerGroups": [],"_viewerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],"_viewerGroups": []}
	})
}

# Member: target allows access via viewerGroups (and target not private)
test_allow_member_when_target_has_viewer_group if {
	allow with input as produce_input_doc_by_role("tarcinapp.member", true, {
		"_fromMetadata": {"_id": "list-1","_validFromDateTime": "2020-01-01T00:00:00Z","_validUntilDateTime": null,"_visibility": "public","_ownerUsers": [],"_ownerGroups": [],"_viewerUsers": [],"_viewerGroups": []},
		"_toMetadata":   {"_id": "entity-1","_validFromDateTime": "2020-01-01T00:00:00Z","_validUntilDateTime": null,"_visibility": "protected","_ownerUsers": [],"_ownerGroups": [],"_viewerUsers": [],"_viewerGroups": ["group-1"]}
	})
}

# ========================================
# MEMBER NEGATIVE TESTS
# ========================================

# Source visible but target not -> deny
test_not_allow_member_when_source_visible_but_target_not if {
	not allow with input as produce_input_doc_by_role("tarcinapp.member", true, {
		"_fromMetadata": {"_id": "list-1","_validFromDateTime": "2020-01-01T00:00:00Z","_validUntilDateTime": null,"_visibility": "public","_ownerUsers": [],"_ownerGroups": [],"_viewerUsers": [],"_viewerGroups": []},
		"_toMetadata":   {"_id": "entity-1","_validFromDateTime": "2020-01-01T00:00:00Z","_validUntilDateTime": null,"_visibility": "private","_ownerUsers": [],"_ownerGroups": [],"_viewerUsers": [],"_viewerGroups": []}
	})
}

# Target visible but source not -> deny
test_not_allow_member_when_target_visible_but_source_not if {
	not allow with input as produce_input_doc_by_role("tarcinapp.member", true, {
		"_fromMetadata": {"_id": "list-1","_validFromDateTime": "2020-01-01T00:00:00Z","_validUntilDateTime": null,"_visibility": "private","_ownerUsers": [],"_ownerGroups": [],"_viewerUsers": [],"_viewerGroups": []},
		"_toMetadata":   {"_id": "entity-1","_validFromDateTime": "2020-01-01T00:00:00Z","_validUntilDateTime": null,"_visibility": "public","_ownerUsers": [],"_ownerGroups": [],"_viewerUsers": [],"_viewerGroups": []}
	})
}

# Source passive/inactive -> deny
test_not_allow_member_when_source_is_passive if {
	not allow with input as produce_input_doc_by_role("tarcinapp.member", true, {
		"_fromMetadata": {"_id": "list-1","_validFromDateTime": "2020-01-01T00:00:00Z","_validUntilDateTime": "2021-01-01T00:00:00Z","_visibility": "public","_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],"_ownerGroups": [],"_viewerUsers": [],"_viewerGroups": []},
		"_toMetadata":   {"_id": "entity-1","_validFromDateTime": "2020-01-01T00:00:00Z","_validUntilDateTime": null,"_visibility": "public","_ownerUsers": [],"_ownerGroups": [],"_viewerUsers": [],"_viewerGroups": []}
	})
}

# Target passive/inactive -> deny
test_not_allow_member_when_target_is_passive if {
	not allow with input as produce_input_doc_by_role("tarcinapp.member", true, {
		"_fromMetadata": {"_id": "list-1","_validFromDateTime": "2020-01-01T00:00:00Z","_validUntilDateTime": null,"_visibility": "public","_ownerUsers": [],"_ownerGroups": [],"_viewerUsers": [],"_viewerGroups": []},
		"_toMetadata":   {"_id": "entity-1","_validFromDateTime": "2020-01-01T00:00:00Z","_validUntilDateTime": "2021-01-01T00:00:00Z","_visibility": "public","_ownerUsers": [],"_ownerGroups": [],"_viewerUsers": [],"_viewerGroups": []}
	})
}

# ========================================
# EDGE CASES and CROSS-SCOPE TESTS
# ========================================

# Owner precedence: direct owner should allow even when record is private
test_allow_member_when_direct_owner_overrides_group_and_private if {
	allow with input as produce_input_doc_by_role("tarcinapp.member", true, {
		"_fromMetadata": {"_id": "list-1","_validFromDateTime": "2020-01-01T00:00:00Z","_validUntilDateTime": null,"_visibility": "private","_ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],"_ownerGroups": ["group-1"],"_viewerUsers": [],"_viewerGroups": []},
		"_toMetadata":   {"_id": "entity-1","_validFromDateTime": "2020-01-01T00:00:00Z","_validUntilDateTime": null,"_visibility": "public","_ownerUsers": [],"_ownerGroups": [],"_viewerUsers": [],"_viewerGroups": []}
	})
}

# viewerGroups on a PRIVATE record must NOT permit access
test_not_allow_member_when_viewerGroups_on_private_visibility if {
	not allow with input as produce_input_doc_by_role("tarcinapp.member", true, {
		"_fromMetadata": {"_id": "list-1","_validFromDateTime": "2020-01-01T00:00:00Z","_validUntilDateTime": null,"_visibility": "public","_ownerUsers": [],"_ownerGroups": [],"_viewerUsers": [],"_viewerGroups": []},
		"_toMetadata":   {"_id": "entity-1","_validFromDateTime": "2020-01-01T00:00:00Z","_validUntilDateTime": null,"_visibility": "private","_ownerUsers": [],"_ownerGroups": [],"_viewerUsers": [],"_viewerGroups": ["group-1"]}
	})
}

# Missing metadata entries should deny (both cases)
test_not_allow_when_missing_fromMetadata if {
	not allow with input as produce_input_doc_by_role("tarcinapp.member", true, {
		"_toMetadata": {"_id": "entity-1","_validFromDateTime": "2020-01-01T00:00:00Z","_validUntilDateTime": null,"_visibility": "public","_ownerUsers": [],"_ownerGroups": [],"_viewerUsers": [],"_viewerGroups": []}
	})
}

test_not_allow_when_missing_toMetadata if {
	not allow with input as produce_input_doc_by_role("tarcinapp.member", true, {
		"_fromMetadata": {"_id": "list-1","_validFromDateTime": "2020-01-01T00:00:00Z","_validUntilDateTime": null,"_visibility": "public","_ownerUsers": [],"_ownerGroups": [],"_viewerUsers": [],"_viewerGroups": []}
	})
}

# Helper to produce test input for findRelationById
produce_input_doc_by_role(roles, is_email_verified, originalRecord) = test_body if {
	test_body = {
		"appShortcode": "tarcinapp",
		"httpMethod": "GET",
		"requestPath": "/relations",
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
		"originalRecord": originalRecord,
	}
}
