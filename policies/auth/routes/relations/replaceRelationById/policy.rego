package policies.auth.routes.relations.replaceRelationById.policy

import data.policies.fields.policy as central_policy
import data.policies.util.common.array as array
import data.policies.util.common.originalRecord as original_record
import data.policies.util.common.token as token
import data.policies.util.common.verification as verification
import data.policies.util.relations.roles as role_utils

# if relation is being approved by a member, validFromDateTime cannot be before than the amount of seconds given below from now
# this option enforces members to approve records immediately
member_validFrom_range_in_seconds := 300

member_validUntil_range_for_inactivation_in_seconds := 300

# By default, deny requests.
default allow := false

# -----------------------------------------------------------------------------
# DYNAMIC FORBIDDEN LISTS
# -----------------------------------------------------------------------------
# These lists are calculated using the central engine.
default forbidden_find_list := []

forbidden_find_list := res if {
	res := central_policy.get_forbidden_fields("relations", "find", input.originalRecord)
}

default forbidden_update_list := []

forbidden_update_list := res if {
	res := central_policy.get_forbidden_fields("relations", "update", input.originalRecord)
}

#-----------------------------------------------
# Decide allow if any of the following section is true
#-----------------------------------------------
allow if {
	role_utils.is_user_admin("update", input.originalRecord)

	# user must be email verified
	verification.is_email_verified

	# payload cannot contain any field that requestor cannot see
	not payload_contains_any_field(forbidden_find_list)

	# forbidden-for-update fields must not be changed
	forbidden_fields_has_same_value_with_original_record
}

allow if {
	role_utils.is_user_editor("update", input.originalRecord)

	# user must be email verified
	verification.is_email_verified

	# payload cannot contain any field that requestor cannot see
	not payload_contains_any_field(forbidden_find_list)

	# forbidden-for-update fields must not be changed
	forbidden_fields_has_same_value_with_original_record
}

allow if {
	role_utils.is_user_member("update", input.originalRecord)

	# user must be email verified
	verification.is_email_verified

	# payload cannot contain any field that requestor cannot see
	not payload_contains_any_field(forbidden_find_list)

	# forbidden-for-update fields must not be changed
	forbidden_fields_has_same_value_with_original_record

	# relation ids must not be changed (members cannot retarget relations)
	is_relation_ids_unchanged

	# caller must own the referenced list (_fromMetadata)
	caller_owns_referenced_list

	# caller must be able to see both the referenced list (_fromMetadata) and the target entity (_toMetadata)
	caller_can_see_from_and_to_metadata

	# members cannot update passive relations
	not original_record.is_passive

	# field-level update constraints for validFrom/validUntil
	not member_has_problem_with_validFrom
	not member_has_problem_with_validUntil
}

#-----------------------------------------------

# helpers
payload_contains_any_field(fields) if {
	some field
	field = fields[_]
	input.requestPayload[field]
}

# if there is no forbidden field for update, this expression must return true
forbidden_fields_has_same_value_with_original_record if {
	not forbidden_update_list[0]
}

forbidden_fields_has_same_value_with_original_record if {
	forbidden_update_list[0]
	not has_forbidden_field_with_different_value
}

has_forbidden_field_with_different_value if {
	some forbidden_field_for_update
	forbidden_field_for_update = forbidden_update_list[_]

	# Don't check if it is already forbidden to find (handled by other check)
	not forbidden_field_for_update in forbidden_find_list

	not has_field(input.requestPayload, forbidden_field_for_update)
}

has_forbidden_field_with_different_value if {
	some forbidden_field_for_update
	forbidden_field_for_update = forbidden_update_list[_]

	not forbidden_field_for_update in forbidden_find_list

	has_field(input.requestPayload, forbidden_field_for_update)
	input.requestPayload[forbidden_field_for_update] != input.originalRecord[forbidden_field_for_update]
}

# relation ids (_listId and _entityId) must not be changed in replace-by-id
is_relation_ids_unchanged if {
	input.requestPayload._listId == input.originalRecord._listId
	input.requestPayload._entityId == input.originalRecord._entityId
}

# The caller must own the referenced list (fromMetadata) - same logic as createRelation
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
	# both metadata parts must exist
	input.originalRecord._fromMetadata
	input.originalRecord._toMetadata
	can_user_see_meta(input.originalRecord._fromMetadata)
	can_user_see_meta(input.originalRecord._toMetadata)
}

# Generic visibility/ownership check using meta object directly (avoid 'with')
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

# helper: check key existence even if value is null
has_field(obj, field) if {
	object.get(obj, field, "__missing__") != "__missing__"
}

# member checks for validFrom/validUntil
member_has_problem_with_validFrom if {
	# If allowed to update, check if value changed?
	# Logic: If it is NOT in forbidden list, it is allowed (by field role or default).
	# But if it is IN forbidden list, we check exceptions.
	not "_validFromDateTime" in forbidden_update_list
	input.requestPayload._validFromDateTime != null
	input.originalRecord._validFromDateTime != null
	input.requestPayload._validFromDateTime != input.originalRecord._validFromDateTime
}

member_has_problem_with_validFrom if {
	not "_validFromDateTime" in forbidden_update_list
	input.originalRecord._validFromDateTime == null
	input.requestPayload._validFromDateTime != null
	not is_validFrom_in_correct_range
}

member_has_problem_with_validUntil if {
	"_validUntilDateTime" in forbidden_find_list
	payload_contains_any_field(["_validUntilDateTime"])
}

member_has_problem_with_validUntil if {
	not "_validUntilDateTime" in forbidden_find_list
	"_validUntilDateTime" in forbidden_update_list
	input.originalRecord._validUntilDateTime == null
	input.requestPayload._validUntilDateTime != input.originalRecord._validUntilDateTime
}

member_has_problem_with_validUntil if {
	not "_validUntilDateTime" in forbidden_find_list
	not "_validUntilDateTime" in forbidden_update_list
	input.originalRecord._validUntilDateTime != null
	input.requestPayload._validUntilDateTime != input.originalRecord._validUntilDateTime
}

member_has_problem_with_validUntil if {
	not "_validUntilDateTime" in forbidden_find_list
	not "_validUntilDateTime" in forbidden_update_list
	input.originalRecord._validUntilDateTime == null
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
