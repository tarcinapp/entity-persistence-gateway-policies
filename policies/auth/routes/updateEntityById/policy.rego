package policies.auth.routes.updateEntityById.policy

import data.policies.util.genericentities.roles as role_utils
import data.policies.fields.genericentities.policy as forbidden_fields
import data.policies.util.common.token as token
import data.policies.util.common.array as array
import data.policies.util.common.verification as verification
import data.policies.util.common.originalRecord as original_record

# if record is being approved by a member, validFromDateTime cannot be before than the amount of seconds given below from now
# this option enforces members to approve records immediately
member_validFrom_range_in_seconds:= 300

member_validUntil_range_for_inactivation_in_seconds := 300

#-----------------------------------------------

# By default, deny requests.
default allow = false
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

# Members are allowed to update the entity if following conditions are met
allow if {
	role_utils.is_user_member("update")
	verification.is_email_verified
	is_record_belongs_to_this_user
	not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_finding)
	forbidden_fields_has_same_value_with_original_record
	user_id_in_ownerUsers
	not member_has_problem_with_ownerGroups
	not member_has_problem_with_validFrom
	not member_has_problem_with_validUntil
}

#-----------------------------------------------

is_record_belongs_to_this_user if {
  original_record.is_belong_to_user
}

is_record_belongs_to_this_user if {
  original_record.is_belong_to_users_groups
  input.originalRecord._visibility != "private"
}

# user_id_in_ownerUsers is a policy control rule.
# It returns true if the payload's ownerUsers field is acceptable for the current user:
# - If ownerUsers is not present in the payload, no check is required (returns true).
# - If ownerUsers is present in the payload and the user was in ownerUsers in the original record,
#   the user must also be present in the payload's ownerUsers.
# - If ownerUsers is present in the payload but the user was not in ownerUsers in the original record,
#   there is no requirement to add the user ID.
user_id_in_ownerUsers if {
    # Pass if ownerUsers is not present in the payload
    not payload_contains_any_field(["_ownerUsers"])
}

user_id_in_ownerUsers if {
    # Pass if ownerUsers is present in the payload and the user was in the original record's ownerUsers,
    # and the user is also present in the payload's ownerUsers
    payload_contains_any_field(["_ownerUsers"])
    original_record.has_value("_ownerUsers")
    user_id_in_list(token.payload.sub, input.originalRecord._ownerUsers)
    user_id_in_list(token.payload.sub, input.requestPayload._ownerUsers)
}

user_id_in_ownerUsers if {
    # Pass if ownerUsers is present in the payload, the original record had ownerUsers,
    # but the user was not in the original record's ownerUsers (no requirement to add user ID)
    payload_contains_any_field(["_ownerUsers"])
    original_record.has_value("_ownerUsers")
    not user_id_in_list(token.payload.sub, input.originalRecord._ownerUsers)
}

# Helper: returns true if user_id is in arr (safe for null arrays)
user_id_in_list(user_id, arr) if {
    arr != null
    some i
    arr[i] == user_id
}

member_has_problem_with_ownerGroups if {
  payload_contains_any_field(["_ownerGroups"])
  no_ownerGroups_item_in_users_groups
}

# This rule checks that every group listed in _ownerGroups in the payload
# is present in the user's group list (from the JWT). If any group in
# _ownerGroups is not found in the user's groups, this rule returns true
# and the update is denied for members.
no_ownerGroups_item_in_users_groups if {
    some i
    group := input.requestPayload._ownerGroups[i]
    not group in token.payload.groups
}



# user can update validFrom
# user tries to change validFrom
# but original value is not null
# As this attempt means changing the approval time, 
# or unapproving already approved reacord, should not be allowed for members
member_has_problem_with_validFrom if {
	payload_contains_any_field(["_validFromDateTime"])
	original_record.has_value("_validFromDateTime")
}

# user can update validFrom
# original value is null
# user tries to add a validFrom
# but validFrom is not in correct range
member_has_problem_with_validFrom if {
	payload_contains_any_field(["_validFromDateTime"])
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
	nowSec := time.now_ns()/(1000*1000*1000)
	validFromSec := time.parse_rfc3339_ns(input.requestPayload._validFromDateTime)/(1000*1000*1000)
    
	validFromSec <= nowSec
    validFromSec > (nowSec - member_validFrom_range_in_seconds)

	validFromDifferenceInSeconds := nowSec-validFromSec
}

is_validUntil_in_correct_range_for_inactivation if {
	nowSec := time.now_ns()/(1000*1000*1000)
    validUntilSec := time.parse_rfc3339_ns(input.requestPayload._validUntilDateTime)/(1000*1000*1000)

    validUntilSec <= nowSec
    validUntilSec > (nowSec - member_validUntil_range_for_inactivation_in_seconds)
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