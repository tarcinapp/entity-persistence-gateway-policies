package policies.auth.routes.replaceEntityById.policy

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

# visitiors cannot update any record

#-----------------------------------------------


# By default, deny requests.
default allow = false
#-----------------------------------------------


# Decide allow if any of the following section is true
#-----------------------------------------------
allow {
	role_utils.is_user_admin("update")

	# user must be email verified
	verification.is_email_verified				

	# payload cannot contain any field that requestor cannot see
    not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_finding)

	forbidden_fields_has_same_value_with_original_record
}


allow {
	role_utils.is_user_editor("update")

	# user must be email verified
	verification.is_email_verified						

	# payload cannot contain any field that requestor cannot see
    not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_finding)

	forbidden_fields_has_same_value_with_original_record
}

allow {
	role_utils.is_user_member("update")

	# payload cannot contain any field that requestor cannot see
    not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_finding)

	forbidden_fields_has_same_value_with_original_record
	
    verification.is_email_verified						# members must be email verified

	is_record_belongs_to_this_user 						# over user's groups or user's id
	not original_record.is_passive 						# only pending and active records are updateable by members for now, maybe we can let users to 'undo' their inactivation operation by letting them to modify inactive records as well

	user_id_in_ownerUsers								# user id must always be in the ownerUsers array
	not member_has_problem_with_ownerGroups				# member cannot use any group name that he is not belongs to
    
	not member_has_problem_with_validFrom				# updating validFrom (approving) requires some specific roles, validFrom > (now - 60s)
	not member_has_problem_with_validUntil				# updating validUntil (deleting) requires some specific roles, (validUntil > now - 60s)
}
#-----------------------------------------------

is_record_belongs_to_this_user {
  original_record.is_belong_to_user
}

is_record_belongs_to_this_user {
  original_record.is_belong_to_users_groups
  input.originalRecord.visibility != "private"
}

user_id_in_ownerUsers {
  input.requestPayload.ownerUsers[_] = token.payload.sub
}

member_has_problem_with_ownerGroups {
  input.requestPayload["ownerGroups"]
  no_ownerGroups_item_in_users_groups
}

no_ownerGroups_item_in_users_groups {
	token.payload.groups[_] != input.requestPayload.ownerGroups[_]
}

# user can update validFrom
# user tries to change validFrom
# but original value is not null
# As this attempt means changing the approval time, 
# or unapproving already approved reacord, should not be allowed for members
member_has_problem_with_validFrom {
	payload_contains_any_field(["validFromDateTime"])
	original_record.has_value("validFromDateTime")
}

# user can update validFrom
# original value is null
# user tries to add a validFrom
# but validFrom is not in correct range
member_has_problem_with_validFrom {
	payload_contains_any_field(["validFromDateTime"])
	not is_validFrom_in_correct_range
}

member_has_problem_with_validUntil {
	payload_contains_any_field(["validUntilDateTime"])
	original_record.has_value("validUntilDateTime")
}

# validUntil must be in correct range for inactivation
member_has_problem_with_validUntil {
	payload_contains_any_field(["validUntilDateTime"])
    not is_validUntil_in_correct_range_for_inactivation
} 

is_validFrom_in_correct_range {
	nowSec := time.now_ns()/(1000*1000*1000)
	validFromSec := time.parse_rfc3339_ns(input.requestPayload.validFromDateTime)/(1000*1000*1000)
    
	validFromSec <= nowSec
    validFromSec > (nowSec - member_validFrom_range_in_seconds)

	validFromDifferenceInSeconds := nowSec-validFromSec
}

is_validUntil_in_correct_range_for_inactivation {
	nowSec := time.now_ns()/(1000*1000*1000)
    validUntilSec := time.parse_rfc3339_ns(input.requestPayload.validUntilDateTime)/(1000*1000*1000)

    validUntilSec <= nowSec
    validUntilSec > (nowSec - member_validUntil_range_for_inactivation_in_seconds)
}

# if there is no forbidden field for update, this expression must return true
forbidden_fields_has_same_value_with_original_record {
	not forbidden_fields.which_fields_forbidden_for_update[0]
}

forbidden_fields_has_same_value_with_original_record {
	forbidden_field_for_update := forbidden_fields.which_fields_forbidden_for_update[_]
	
	input.requestPayload[forbidden_field_for_update] = input.originalRecord[forbidden_field_for_update]
}

payload_contains_any_field(fields) {
    field = fields[_]
    input.requestPayload[field]
}