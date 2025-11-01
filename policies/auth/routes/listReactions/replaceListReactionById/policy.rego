package policies.auth.routes.listReactions.replaceListReactionById.policy

import data.policies.fields.listReactions.policy as forbidden_fields
import data.policies.util.common.array as array
import data.policies.util.common.originalRecord as original_record
import data.policies.util.common.token as token
import data.policies.util.common.verification as verification
import data.policies.util.listReactions.roles as role_utils
import data.policies.util.lists.roles as list_role_utils

# By default, deny requests.
default allow := false

# Admins
allow if {
	role_utils.is_user_admin("update")
	verification.is_email_verified
	not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_finding)
	forbidden_fields_has_same_value_with_original_record
	can_see_related_list
}

# Editors
allow if {
	role_utils.is_user_editor("update")
	verification.is_email_verified
	not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_finding)
	forbidden_fields_has_same_value_with_original_record
	can_see_related_list
}

# Members
allow if {
	role_utils.is_user_member("update")
	verification.is_email_verified
	not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_finding)
	forbidden_fields_has_same_value_with_original_record
	is_record_belongs_to_this_user
	not original_record.is_passive
	not member_has_problem_with_validFrom
	not member_has_problem_with_validUntil
	can_see_related_list
}

# --- Managed fields logic (copied from replaceEntityById) ---
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
	not original_record.is_private
	input.requestPayload._visibility != "private"
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

no_original_groups_removed if {
	not has_removed_groups
}

no_original_groups_removed if {
	has_removed_groups
	all_original_groups_still_present
}

has_removed_groups if {
	some original_group
	original_group = input.originalRecord._ownerGroups[_]
	not group_in_request_payload(original_group)
}

all_original_groups_still_present if {
	some original_group
	original_group = input.originalRecord._ownerGroups[_]
	group_in_request_payload(original_group)
	not has_removed_group
}

has_removed_group if {
	some original_group
	original_group = input.originalRecord._ownerGroups[_]
	not group_in_request_payload(original_group)
}

group_in_request_payload(group) if {
	some i
	input.requestPayload._ownerGroups[i] == group
}

all_new_groups_from_user_groups if {
	not has_new_groups
}

all_new_groups_from_user_groups if {
	has_new_groups
	all_new_groups_are_from_user_groups
}

has_new_groups if {
	some new_group
	new_group = input.requestPayload._ownerGroups[_]
	not group_in_original_record(new_group)
}

all_new_groups_are_from_user_groups if {
	some new_group
	new_group = input.requestPayload._ownerGroups[_]
	not group_in_original_record(new_group)
	group_in_token_groups(new_group)
	not has_new_group_not_from_user_groups
}

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

ownerUsers_unchanged if {
	not has_removed_users
	not has_added_users
}

has_removed_users if {
	some original_user
	original_user = input.originalRecord._ownerUsers[_]
	not user_in_request_payload(original_user)
}

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

member_has_problem_with_validFrom if {
	not "_validFromDateTime" in forbidden_fields.which_fields_forbidden_for_update
	input.requestPayload._validFromDateTime != null
	input.originalRecord._validFromDateTime != null
	input.requestPayload._validFromDateTime != input.originalRecord._validFromDateTime
}

member_has_problem_with_validFrom if {
	not "_validFromDateTime" in forbidden_fields.which_fields_forbidden_for_update
	input.originalRecord._validFromDateTime == null
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
	input.originalRecord._validUntilDateTime == null
	input.requestPayload._validUntilDateTime != input.originalRecord._validUntilDateTime
}

member_has_problem_with_validUntil if {
	not "_validUntilDateTime" in forbidden_fields.which_fields_forbidden_for_finding
	not "_validUntilDateTime" in forbidden_fields.which_fields_forbidden_for_update
	input.originalRecord._validUntilDateTime != null
	input.requestPayload._validUntilDateTime != input.originalRecord._validUntilDateTime
}

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
	validFromSec > nowSec - 300
}

is_validUntil_in_correct_range_for_inactivation if {
	payload_contains_any_field(["_validUntilDateTime"])
	input.requestPayload._validUntilDateTime != null
	nowSec := time.now_ns() / ((1000 * 1000) * 1000)
	validUntilSec := time.parse_rfc3339_ns(input.requestPayload._validUntilDateTime) / ((1000 * 1000) * 1000)
	validUntilSec <= nowSec
	validUntilSec > nowSec - 300
}

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

# --- Related list visibility check (using managed fields, like findListById) ---
can_see_related_list if {
	related := input.originalRecord._relationMetadata

	# Admin
	list_role_utils.is_user_admin("find")
	verification.is_email_verified
}

can_see_related_list if {
	related := input.originalRecord._relationMetadata

	# Editor
	list_role_utils.is_user_editor("find")
	verification.is_email_verified
}

can_see_related_list if {
	related := input.originalRecord._relationMetadata

	# Member
	list_role_utils.is_user_member("find")
	verification.is_email_verified
	can_user_see_this_related_list
}

can_see_related_list if {
	related := input.originalRecord._relationMetadata

	# Visitor
	list_role_utils.is_user_visitor("find")
	verification.is_email_verified
	is_related_list_public_and_active
}

# --- Related list visibility logic (mirroring findListById managed fields) ---
can_user_see_this_related_list if {
	related := input.originalRecord._relationMetadata
	is_related_list_belong_to_user
	not is_related_list_passive
}

can_user_see_this_related_list if {
	related := input.originalRecord._relationMetadata
	is_related_list_belong_to_users_groups
	not is_related_list_passive
	not is_related_list_private
}

can_user_see_this_related_list if {
	related := input.originalRecord._relationMetadata
	is_related_list_public_and_active
}

can_user_see_this_related_list if {
	related := input.originalRecord._relationMetadata
	is_related_list_user_in_viewerUsers
	is_related_list_active
}

can_user_see_this_related_list if {
	related := input.originalRecord._relationMetadata
	is_related_list_user_in_viewerGroups
	not is_related_list_private
	is_related_list_active
}

# --- Managed field helpers for related list ---
is_related_list_belong_to_user if {
	some i
	token.payload.sub == input.originalRecord._relationMetadata._ownerUsers[i]
}

is_related_list_belong_to_users_groups if {
	not is_related_list_belong_to_user
	some i
	token.payload.groups[i] == input.originalRecord._relationMetadata._ownerGroups[_]
}

is_related_list_private if {
	input.originalRecord._relationMetadata._visibility == "private"
}

is_related_list_public_and_active if {
	is_related_list_public
	is_related_list_active
}

is_related_list_public if {
	input.originalRecord._relationMetadata._visibility == "public"
}

is_related_list_active if {
	input.originalRecord._relationMetadata._validFromDateTime != null
	time.parse_rfc3339_ns(input.originalRecord._relationMetadata._validFromDateTime) < time.now_ns()
	not is_related_list_passive
}

is_related_list_passive if {
	input.originalRecord._relationMetadata._validUntilDateTime != null
	time.parse_rfc3339_ns(input.originalRecord._relationMetadata._validUntilDateTime) <= time.now_ns()
}

is_related_list_user_in_viewerUsers if {
	some i
	token.payload.sub == input.originalRecord._relationMetadata._viewerUsers[i]
}

is_related_list_user_in_viewerGroups if {
	some i
	token.payload.groups[i] == input.originalRecord._relationMetadata._viewerGroups[_]
}
