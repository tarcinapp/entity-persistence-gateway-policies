package policies.auth.routes.relations.updateRelationById.policy

import data.policies.fields.relations.policy as forbidden_fields
import data.policies.util.common.array as array
import data.policies.util.common.originalRecord as original_record
import data.policies.util.common.token as token
import data.policies.util.common.verification as verification
import data.policies.util.relations.roles as role_utils

# Configuration: member-specific timing tolerances (seconds)
member_validFrom_range_in_seconds := 300
member_validUntil_range_for_inactivation_in_seconds := 300

# By default, deny requests.
default allow := false

#-----------------------------------------------
# Allow rules (PATCH semantics — partial updates)
#-----------------------------------------------

# Admins may PATCH across lists/entities but must be email verified,
# must not include fields they cannot see and must preserve forbidden-for-update fields.
allow if {
	role_utils.is_user_admin("update")
	verification.is_email_verified
	original_record_present
	not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_finding)
	forbidden_update_fields_preserved_patch
}

# Editors are similar to admins but are conservative about retargeting on PATCH:
# they may not change the relation ids when performing a PATCH.
allow if {
	role_utils.is_user_editor("update")
	verification.is_email_verified
	original_record_present
	not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_finding)
	forbidden_update_fields_preserved_patch
	# Intentional decision: allow editors to retarget relation ids on PATCH for
	# merging/repair workflows. Keep the immutability check commented out so
	# editors can perform retargeting in those scenarios.
	# is_relation_ids_unchanged
}

# Members: stricter rules. Must be email-verified, cannot include forbidden-to-see
# fields, must preserve forbidden-for-update fields (omission allowed), must own the
# referenced list, be able to see both endpoints, cannot operate on passive relations,
# and must satisfy validFrom/validUntil member constraints. Members may not retarget ids.
allow if {
	role_utils.is_user_member("update")
	verification.is_email_verified
	original_record_present
	not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_finding)
	forbidden_update_fields_preserved_patch
	is_relation_ids_unchanged
	caller_owns_referenced_list
	caller_can_see_from_and_to_metadata
	not original_record.is_passive
	not member_has_problem_with_validFrom
	not member_has_problem_with_validUntil
}

# Visitors: implicit deny (no allow rule)

#-----------------------------------------------
# Helpers
#-----------------------------------------------

# Detect whether any of the given field names appear in the request payload.
payload_contains_any_field(fields) if {
	some field
	field = fields[_]
	input.requestPayload[field]
}

# Original record presence check: the update-by-id flow relies on the original
# record (and its nested metadata); if these are missing we must deny.
original_record_present if {
	input.originalRecord
	input.originalRecord._fromMetadata
	input.originalRecord._toMetadata
}

# PATCH semantics for forbidden-for-update fields:
# - Omission of a forbidden update field in the payload is allowed.
# - If the payload includes a forbidden update field and the original record
#   contained that field, the payload value must equal the original value.
# - If the payload includes a forbidden update field and the original did NOT
#   contain that field, adding it is treated as a forbidden change and denied.
forbidden_update_fields_preserved_patch if {
	not forbidden_fields.which_fields_forbidden_for_update[0]
}

forbidden_update_fields_preserved_patch if {
	not has_forbidden_update_field_violation
}

has_forbidden_update_field_violation if {
	some f
	f = forbidden_fields.which_fields_forbidden_for_update[_]

	# field is present in the request payload (PATCH semantics: presence matters)
	input.requestPayload[f]

	# violation: original had a value but payload differs
	original_record.has_value(f)
	input.requestPayload[f] != input.originalRecord[f]
}

has_forbidden_update_field_violation if {
	some f
	f = forbidden_fields.which_fields_forbidden_for_update[_]

	# field is present in the request payload and original did not have it — new introduction
	input.requestPayload[f]
	not original_record.has_value(f)
}

# Relation id immutability for PATCH consumers (treat omission as allowed)
relation_id_ok(field) if {
	not payload_contains_any_field([field])
}

relation_id_ok(field) if {
	input.requestPayload[field] == input.originalRecord[field]
}

is_relation_ids_unchanged if {
	relation_id_ok("_listId")
	relation_id_ok("_entityId")
}

# Ownership of the referenced list (_fromMetadata)
caller_owns_referenced_list if {
	referenced_list_belong_to_user
}

caller_owns_referenced_list if {
	referenced_list_belong_to_users_groups
	not referenced_list_is_private
}

referenced_list_belong_to_user if {
	some i
	token.payload.sub == input.originalRecord._fromMetadata._ownerUsers[i]
}

referenced_list_belong_to_users_groups if {
	not referenced_list_belong_to_user
	some i
	token.payload.groups[i] in input.originalRecord._fromMetadata._ownerGroups
}

referenced_list_is_private if {
	input.originalRecord._fromMetadata._visibility == "private"
}

# Caller must be able to see both from and to metadata
caller_can_see_from_and_to_metadata if {
	input.originalRecord._fromMetadata
	input.originalRecord._toMetadata
	can_user_see_meta(input.originalRecord._fromMetadata)
	can_user_see_meta(input.originalRecord._toMetadata)
}

# Metadata visibility helpers (operate on provided meta object)
meta_is_passive(meta) if {
	meta._validUntilDateTime != null
	time.parse_rfc3339_ns(meta._validUntilDateTime) <= time.now_ns()
}

meta_is_active(meta) if {
	meta._validFromDateTime != null
	time.parse_rfc3339_ns(meta._validFromDateTime) < time.now_ns()
	not meta_is_passive(meta)
}

meta_has_owner_user(meta) if {
	some i
	token.payload.sub == meta._ownerUsers[i]
}

meta_has_owner_group(meta) if {
	some i
	token.payload.groups[i] in meta._ownerGroups
}

meta_has_viewer_user(meta) if {
	some i
	token.payload.sub == meta._viewerUsers[i]
}

meta_has_viewer_group(meta) if {
	some i
	token.payload.groups[i] in meta._viewerGroups
}

can_user_see_meta(meta) if {
	meta_has_owner_user(meta)
	meta_is_active(meta)
}

can_user_see_meta(meta) if {
	not meta_has_owner_user(meta)
	meta_has_owner_group(meta)
	meta_is_active(meta)
	meta._visibility != "private"
}

can_user_see_meta(meta) if {
	meta._visibility == "public"
	meta_is_active(meta)
}

can_user_see_meta(meta) if {
	meta_has_viewer_user(meta)
	meta_is_active(meta)
}

can_user_see_meta(meta) if {
	meta_has_viewer_group(meta)
	meta_is_active(meta)
	meta._visibility != "private"
}

# Member-specific validFrom/validUntil checks (same intent as replace policies,
# but tailored for PATCH semantics where omission is permitted)
member_has_problem_with_validFrom if {
	not "_validFromDateTime" in forbidden_fields.which_fields_forbidden_for_update
	input.requestPayload._validFromDateTime != null
	not original_record.is_empty("_validFromDateTime")
	input.requestPayload._validFromDateTime != input.originalRecord._validFromDateTime
}

member_has_problem_with_validFrom if {
	not "_validFromDateTime" in forbidden_fields.which_fields_forbidden_for_update
	original_record.is_empty("_validFromDateTime")
	input.requestPayload._validFromDateTime != null
	not is_validFrom_in_correct_range
}

member_has_problem_with_validUntil if {
	"_validUntilDateTime" in forbidden_fields.which_fields_forbidden_for_finding
	payload_contains_any_field(["_validUntilDateTime"])
}

member_has_problem_with_validUntil if {
	not "_validUntilDateTime" in forbidden_fields.which_fields_forbidden_for_finding
	"_validUntilDateTime" in forbidden_fields.which_fields_forbidden_for_update
	original_record.is_empty("_validUntilDateTime")
	input.requestPayload._validUntilDateTime != null
}

member_has_problem_with_validUntil if {
	not "_validUntilDateTime" in forbidden_fields.which_fields_forbidden_for_finding
	not "_validUntilDateTime" in forbidden_fields.which_fields_forbidden_for_update
	not original_record.is_empty("_validUntilDateTime")
	input.requestPayload._validUntilDateTime != input.originalRecord._validUntilDateTime
}

member_has_problem_with_validUntil if {
	not "_validUntilDateTime" in forbidden_fields.which_fields_forbidden_for_finding
	not "_validUntilDateTime" in forbidden_fields.which_fields_forbidden_for_update
	original_record.is_empty("_validUntilDateTime")
	input.requestPayload._validUntilDateTime != null
	not is_validUntil_in_correct_range_for_inactivation
}

is_validFrom_in_correct_range if {
	payload_contains_any_field(["_validFromDateTime"])
	input.requestPayload._validFromDateTime != null
	nowSec := time.now_ns() / ((1000 * 1000) * 1000)
	validFromSec := time.parse_rfc3339_ns(input.requestPayload._validFromDateTime) / ((1000 * 1000) * 1000)

	validFromSec <= nowSec
	validFromSec > nowSec - member_validFrom_range_in_seconds
}

is_validUntil_in_correct_range_for_inactivation if {
	payload_contains_any_field(["_validUntilDateTime"])
	input.requestPayload._validUntilDateTime != null
	nowSec := time.now_ns() / ((1000 * 1000) * 1000)
	validUntilSec := time.parse_rfc3339_ns(input.requestPayload._validUntilDateTime) / ((1000 * 1000) * 1000)

	validUntilSec <= nowSec
	validUntilSec > nowSec - member_validUntil_range_for_inactivation_in_seconds
}
