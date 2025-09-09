package policies.auth.routes.replaceEntityById.policy

import data.policies.fields.entities.policy as forbidden_fields
import data.policies.util.common.array as array
import data.policies.util.common.originalRecord as original_record
import data.policies.util.common.token as token
import data.policies.util.common.verification as verification
import data.policies.util.entities.roles as role_utils

# if record is being approved by a member, validFromDateTime cannot be before than the amount of seconds given below from now
# this option enforces members to approve records immediately
member_validFrom_range_in_seconds := 300

member_validUntil_range_for_inactivation_in_seconds := 300

# visitors cannot update any record

#-----------------------------------------------

# By default, deny requests.
default allow = false

#-----------------------------------------------

# Decide allow if any of the following section is true
#-----------------------------------------------
allow if {
	role_utils.is_user_admin("update")

	# user must be email verified
	verification.is_email_verified

	# payload cannot contain any field that requestor cannot see
	not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_finding)

	forbidden_fields_has_same_value_with_original_record
}

allow if {
	role_utils.is_user_editor("update")

	# user must be email verified
	verification.is_email_verified

	# payload cannot contain any field that requestor cannot see
	not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_finding)

	forbidden_fields_has_same_value_with_original_record
}

allow if {
	role_utils.is_user_member("update")

	# payload cannot contain any field that requestor cannot see
	not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_finding)

	forbidden_fields_has_same_value_with_original_record

	verification.is_email_verified # members must be email verified

	is_record_belongs_to_this_user # over user's groups or user's id
	not original_record.is_passive # only pending and active records are updateable by members for now, maybe we can let users to 'undo' their inactivation operation by letting them to modify inactive records as well

	not member_has_problem_with_validFrom # updating validFrom (approving) requires some specific roles, validFrom > (now - 60s)
	not member_has_problem_with_validUntil # updating validUntil (deleting) requires some specific roles, (validUntil > now - 60s)
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
	not original_record.is_private                # record is either public or protected
	input.requestPayload._visibility != "private" # user cannot change visibility to private
	all_new_groups_from_user_groups
	no_original_groups_removed
	ownerUsers_unchanged
}

user_id_in_ownerUsers if {
	some i
	input.requestPayload._ownerUsers[i] == token.payload.sub
}

group_in_token_groups(group) if {
	some i
	token.payload.groups[i] == group
}

# all groups in the originalRecord's _ownerGroups must still be in the requestPayload._ownerGroups
# meaning no group is removed
# returns true if no groups are removed OR if all original groups are still present
no_original_groups_removed if {
	not has_removed_groups
}

no_original_groups_removed if {
	has_removed_groups
	all_original_groups_still_present
}

# check if there are any groups that were removed (groups in original that aren't in request)
has_removed_groups if {
	some original_group
	original_group = input.originalRecord._ownerGroups[_]
	not group_in_request_payload(original_group)
}

# check if all original groups are still present in request payload
all_original_groups_still_present if {
	some original_group
	original_group = input.originalRecord._ownerGroups[_]
	group_in_request_payload(original_group)
	not has_removed_group
}

# check if there are any original groups that are NOT in request payload
has_removed_group if {
	some original_group
	original_group = input.originalRecord._ownerGroups[_]
	not group_in_request_payload(original_group)
}

group_in_request_payload(group) if {
	some i
	input.requestPayload._ownerGroups[i] == group
}

# all newly added groups in the requestPayload._ownerGroups are from the user's own groups
# returns true if there are no new groups OR if all new groups are from user's groups
all_new_groups_from_user_groups if {
	not has_new_groups
}

all_new_groups_from_user_groups if {
	has_new_groups
	all_new_groups_are_from_user_groups
}

# check if there are any new groups (groups in request payload that weren't in original)
has_new_groups if {
	some new_group
	new_group = input.requestPayload._ownerGroups[_]
	not group_in_original_record(new_group)
}

# check if all new groups are from user's groups
all_new_groups_are_from_user_groups if {
	some new_group
	new_group = input.requestPayload._ownerGroups[_]
	not group_in_original_record(new_group)
	group_in_token_groups(new_group)
	not has_new_group_not_from_user_groups
}

# check if there are any new groups that are NOT from user's groups
has_new_group_not_from_user_groups if {
	some new_group
	new_group = input.requestPayload._ownerGroups[_]
	not group_in_original_record(new_group)
	not group_in_token_groups(new_group)
}

group_in_original_record(group) if {
	some i
	input.originalRecord._ownerGroups[i] == group
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

# if user cannot find the field, he cannot send the field in the request payload
# purpose: to prevent users from sending fields that they cannot see
member_has_problem_with_validUntil if {
	"_validUntilDateTime" in forbidden_fields.which_fields_forbidden_for_finding
	payload_contains_any_field(["_validUntilDateTime"])
}

# if user can 
#   find the _validUntilDateTime field and,
#   cannot update it because of the lack of the field level role and,
#   original value is null
# then
#   he cannot send any value than null for the _validUntilDateTime field
# purpose: to prevent users from sending different values than the original value if he does not have the field level role to update it
member_has_problem_with_validUntil if {
	not "_validUntilDateTime" in forbidden_fields.which_fields_forbidden_for_finding
	"_validUntilDateTime" in forbidden_fields.which_fields_forbidden_for_update
	input.originalRecord._validUntilDateTime == null
	input.requestPayload._validUntilDateTime != input.originalRecord._validUntilDateTime
}

# if user can 
#   find the _validUntilDateTime field and,
#   can update it because of the field level role and,
#   field has a value in the original record
# then
#   he cannot send any value different than the original value for the _validUntilDateTime field
# purpose: if original validUntilDateTime is not null, user cannot set anything different than the original value
member_has_problem_with_validUntil if {
	not "_validUntilDateTime" in forbidden_fields.which_fields_forbidden_for_finding
	not "_validUntilDateTime" in forbidden_fields.which_fields_forbidden_for_update
	input.originalRecord._validUntilDateTime != null
	input.requestPayload._validUntilDateTime != input.originalRecord._validUntilDateTime
}

# if user can 
#   find the _validUntilDateTime field and,
#   can update it because of the field level role and,
#   field has no value in the original record
# then
#   he cannot send any value that is not in the correct range for inactivation
member_has_problem_with_validUntil if {
	not "_validUntilDateTime" in forbidden_fields.which_fields_forbidden_for_finding
	not "_validUntilDateTime" in forbidden_fields.which_fields_forbidden_for_update
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

	validFromDifferenceInSeconds := nowSec - validFromSec
}

is_validUntil_in_correct_range_for_inactivation if {
	payload_contains_any_field(["_validUntilDateTime"])
	input.requestPayload._validUntilDateTime != null
	nowSec := time.now_ns() / ((1000 * 1000) * 1000)
	validUntilSec := time.parse_rfc3339_ns(input.requestPayload._validUntilDateTime) / ((1000 * 1000) * 1000)

	validUntilSec <= nowSec
	validUntilSec > nowSec - member_validUntil_range_for_inactivation_in_seconds
}

# if there is no forbidden field for update, this expression must return true
forbidden_fields_has_same_value_with_original_record if {
	not forbidden_fields.which_fields_forbidden_for_update[0]
}

forbidden_fields_has_same_value_with_original_record if {
	some forbidden_field_for_update
	forbidden_field_for_update = forbidden_fields.which_fields_forbidden_for_update[_]

	input.requestPayload[forbidden_field_for_update] == input.originalRecord[forbidden_field_for_update]
}

payload_contains_any_field(fields) if {
	some field
	field = fields[_]
	input.requestPayload[field]
}
