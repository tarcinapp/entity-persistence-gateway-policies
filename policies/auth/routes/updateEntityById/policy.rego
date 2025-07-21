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

# if ownerUsers exists in the payload, then it must contains user's id
# if ownerUsers is not in the payload, then we can assume this control 'true'
user_id_in_ownerUsers if {
	not payload_contains_any_field(["ownerUsers"])
}

user_id_in_ownerUsers if {
	payload_contains_any_field(["ownerUsers"])
	input.requestPayload.ownerUsers[_] = token.payload.sub
}

member_has_problem_with_ownerGroups if {
  payload_contains_any_field(["ownerGroups"])
  no_ownerGroups_item_in_users_groups
}

no_ownerGroups_item_in_users_groups if {
	token.payload.groups[_] != input.requestPayload.ownerGroups[_]
}

# user can update validFrom
# user tries to change validFrom
# but original value is not null
# As this attempt means changing the approval time, 
# or unapproving already approved reacord, should not be allowed for members
member_has_problem_with_validFrom if {
	payload_contains_any_field(["validFromDateTime"])
	original_record.has_value("validFromDateTime")
}

# user can update validFrom
# original value is null
# user tries to add a validFrom
# but validFrom is not in correct range
member_has_problem_with_validFrom if {
	payload_contains_any_field(["validFromDateTime"])
	not is_validFrom_in_correct_range
}

member_has_problem_with_validUntil if {
	payload_contains_any_field(["validUntilDateTime"])
	original_record.has_value("validUntilDateTime")
}

# validUntil must be in correct range for inactivation
member_has_problem_with_validUntil if {
	payload_contains_any_field(["validUntilDateTime"])
    not is_validUntil_in_correct_range_for_inactivation
} 

is_validFrom_in_correct_range if {
	nowSec := time.now_ns()/(1000*1000*1000)
	validFromSec := time.parse_rfc3339_ns(input.requestPayload.validFromDateTime)/(1000*1000*1000)
    
	validFromSec <= nowSec
    validFromSec > (nowSec - member_validFrom_range_in_seconds)

	validFromDifferenceInSeconds := nowSec-validFromSec
}

is_validUntil_in_correct_range_for_inactivation if {
	nowSec := time.now_ns()/(1000*1000*1000)
    validUntilSec := time.parse_rfc3339_ns(input.requestPayload.validUntilDateTime)/(1000*1000*1000)

    validUntilSec <= nowSec
    validUntilSec > (nowSec - member_validUntil_range_for_inactivation_in_seconds)
}

# if there is no forbidden field for update, this expression must return true
forbidden_fields_has_same_value_with_original_record if {
	not forbidden_fields.which_fields_forbidden_for_update[0]
}

forbidden_fields_has_same_value_with_original_record if {
	forbidden_field_for_update := forbidden_fields.which_fields_forbidden_for_update[_]
	
	input.requestPayload[forbidden_field_for_update] = input.originalRecord[forbidden_field_for_update]
}

payload_contains_any_field(fields) if {
    field = fields[_]
    input.requestPayload[field]
}

# Helper functions
#-----------------------------------------------
is_owner_users_empty if {
    count(input.originalRecord.ownerUsers) == 0
}

is_owner_groups_empty if {
    count(input.originalRecord.ownerGroups) == 0
}

#-----------------------------------------------