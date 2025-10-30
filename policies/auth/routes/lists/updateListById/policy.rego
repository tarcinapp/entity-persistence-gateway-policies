package policies.auth.routes.lists.updateListById.policy

import data.policies.fields.lists.policy as forbidden_fields
import data.policies.util.common.array as array
import data.policies.util.common.originalRecord as original_record
import data.policies.util.common.token as token
import data.policies.util.common.verification as verification
import data.policies.util.lists.roles as role_utils

# if record is being approved by a member, validFromDateTime cannot be before than the amount of seconds given below from now
# this option enforces members to approve records immediately
member_validFrom_range_in_seconds := 300

member_validUntil_range_for_inactivation_in_seconds := 300

#-----------------------------------------------

# By default, deny requests.
default allow := false

#-----------------------------------------------

# Admin users are allowed to update the original record notwithstanding the payload and original record
allow if {
	role_utils.is_user_admin("update")
	verification.is_email_verified
	not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_finding)
	forbidden_fields_has_same_value_with_original_record
}

# Editor users are allowed to update the record if payload satisfy 'all' of the conditions
allow if {
	role_utils.is_user_editor("update")
	verification.is_email_verified
	not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_finding)
	forbidden_fields_has_same_value_with_original_record
}

# Members are allowed to update the list if following conditions are met
allow if {
	role_utils.is_user_member("update")
	verification.is_email_verified
	is_record_belongs_to_this_user # This will check either through user_id or groups
	not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_finding)
	forbidden_fields_has_same_value_with_original_record
	not member_has_problem_with_validFrom
	not member_has_problem_with_validUntil
}

#-----------------------------------------------

is_record_belongs_to_this_user if {
	is_record_belongs_to_this_user_through_user_id
}

is_record_belongs_to_this_user if {
	is_record_belongs_to_this_user_through_groups
}

is_record_belongs_to_this_user_through_user_id if {
	original_record.is_belong_to_user
	user_id_in_ownerUsers
	all_new_groups_from_user_groups
}

is_record_belongs_to_this_user_through_groups if {
	original_record.is_belong_to_users_groups
	not original_record.is_private # record must be public or protected
	not has_visibility_change_to_private # cannot change to private
	all_new_groups_from_user_groups # new groups must be from user's groups
	no_original_groups_removed # cannot remove original groups
	ownerUsers_unchanged # cannot modify ownerUsers
}

has_visibility_change_to_private if {
	payload_contains_any_field(["_visibility"])
	input.requestPayload._visibility == "private"
}

user_id_in_ownerUsers if {
	# Pass if ownerUsers is not in payload (no change)
	not payload_contains_any_field(["_ownerUsers"])
}

user_id_in_ownerUsers if {
	# For user-owned records, user ID must be in payload's ownerUsers
	original_record.is_belong_to_user
	not original_record.is_belong_to_users_groups
	input.requestPayload._ownerUsers[_] == token.payload.sub
}

user_id_in_ownerUsers if {
	# Pass if owned through groups only
	not original_record.is_belong_to_user
	original_record.is_belong_to_users_groups
}

all_new_groups_from_user_groups if {
	# Pass if no ownerGroups in payload (no change)
	not payload_contains_any_field(["_ownerGroups"])
}

all_new_groups_from_user_groups if {
	# All groups in payload must be user's groups
	payload_contains_any_field(["_ownerGroups"])
	every group in input.requestPayload._ownerGroups {
		group in token.payload.groups
	}
}

no_original_groups_removed if {
	# Pass if no ownerGroups in payload (no change)
	not payload_contains_any_field(["_ownerGroups"])
}

no_original_groups_removed if {
	# All original groups must be in payload
	payload_contains_any_field(["_ownerGroups"])
	every group in input.originalRecord._ownerGroups {
		group in input.requestPayload._ownerGroups
	}
}

# all items in requestPayload._ownerUsers are same with all items in originalRecord._ownerUsers
# returns true if owner users are unchanged (no additions, no removals)
ownerUsers_unchanged if {
	not has_removed_users
	not has_added_users
}

# check if there are any users that were removed (users in original that aren't in request)
has_removed_users if {
	some original_user
	original_user = input.originalRecord._ownerUsers[_]
	not user_in_request_payload(original_user)
}

# check if there are any users that were added (users in request that weren't in original)
has_added_users if {
	some request_user
	request_user = input.requestPayload._ownerUsers[_]
	not user_in_original_record(request_user)
}

user_in_request_payload(user) if {
	some i
	input.requestPayload._ownerUsers[i] == user
}

user_in_original_record(user) if {
	some i
	input.originalRecord._ownerUsers[i] == user
}

# user can update validFrom
# user tries to change validFrom
# but original value is not null
# As this attempt means changing the approval time,
# or unapproving already approved reacord, should not be allowed for members
# user can only send same value for validFrom
member_has_problem_with_validFrom if {
	not "_validFromDateTime" in forbidden_fields.which_fields_forbidden_for_update
	input.requestPayload._validFromDateTime != null
	input.originalRecord._validFromDateTime != null
	input.requestPayload._validFromDateTime != input.originalRecord._validFromDateTime
}

# user can update validFrom
# original value is null
# user tries to add a validFrom
# but validFrom is not in correct range
member_has_problem_with_validFrom if {
	not "_validFromDateTime" in forbidden_fields.which_fields_forbidden_for_update
	input.originalRecord._validFromDateTime == null
	input.requestPayload._validFromDateTime != null
	not is_validFrom_in_correct_range
}

# Helper: true if _validUntilDateTime is forbidden for update for this user
validUntil_forbidden if {
	forbidden_fields.which_fields_forbidden_for_update[_] == "_validUntilDateTime"
}

# Case 1: If the original value is not null, members cannot update or clear it
member_has_problem_with_validUntil if {
	payload_contains_any_field(["_validUntilDateTime"])
	original_record.has_value("_validUntilDateTime")
	input.originalRecord._validUntilDateTime != null
	input.requestPayload._validUntilDateTime != input.originalRecord._validUntilDateTime
}

# Case 2a: Original does not have the field at all and field is forbidden for update
member_has_problem_with_validUntil if {
	payload_contains_any_field(["_validUntilDateTime"])
	not original_record.has_value("_validUntilDateTime")
	validUntil_forbidden
	input.requestPayload._validUntilDateTime != null
}

# Case 2b: Original has the field and it is null, field is forbidden for update
member_has_problem_with_validUntil if {
	payload_contains_any_field(["_validUntilDateTime"])
	input.originalRecord._validUntilDateTime == null
	validUntil_forbidden
	input.requestPayload._validUntilDateTime != null
}

# Case 3a: Original does not have the field at all, user has update permission
member_has_problem_with_validUntil if {
	payload_contains_any_field(["_validUntilDateTime"])
	not original_record.has_value("_validUntilDateTime")
	not validUntil_forbidden
	input.requestPayload._validUntilDateTime != null
	not is_validUntil_in_correct_range_for_inactivation
}

# Case 3b: Original has the field and it is null, user has update permission
member_has_problem_with_validUntil if {
	payload_contains_any_field(["_validUntilDateTime"])
	input.originalRecord._validUntilDateTime == null
	not validUntil_forbidden
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

	validFromDifferenceInSeconds := nowSec - validFromSec
}

is_validUntil_in_correct_range_for_inactivation if {
	nowSec := time.now_ns() / ((1000 * 1000) * 1000)
	validUntilSec := time.parse_rfc3339_ns(input.requestPayload._validUntilDateTime) / ((1000 * 1000) * 1000)

	validUntilSec <= nowSec
	validUntilSec > nowSec - member_validUntil_range_for_inactivation_in_seconds
}

# Returns true if there exists a forbidden field for update in the payload with a different value
forbidden_update_field_changed if {
	field := forbidden_fields.which_fields_forbidden_for_update[_]
	input.requestPayload[field]
	input.requestPayload[field] != input.originalRecord[field]
}

# All forbidden-for-update fields present in the payload must have the same value as in the original record
forbidden_fields_has_same_value_with_original_record if {
	not forbidden_update_field_changed
}

payload_contains_any_field(fields) if {
	field = fields[_]
	input.requestPayload[field]
}

# Helper functions
#-----------------------------------------------
is_owner_users_empty if {
	count(input.originalRecord._ownerUsers) == 0
}

is_owner_groups_empty if {
	count(input.originalRecord._ownerGroups) == 0
}

#-----------------------------------------------
