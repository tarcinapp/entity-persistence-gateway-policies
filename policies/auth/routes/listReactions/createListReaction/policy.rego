package policies.auth.routes.listReactions.createListReaction.policy

import data.policies.fields.listReactions.policy as forbidden_fields
import data.policies.util.common.array as array
import data.policies.util.common.token as token
import data.policies.util.common.verification as verification
import data.policies.util.listReactions.roles as role_utils

# By default, deny requests.
default allow := false

# Decide allow if any of the following section is true
# ----------------------------------------------
allow if {
	role_utils.is_user_admin("create")
	verification.is_email_verified

	# payload cannot contain any invalid field
	not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_create)
}

allow if {
	role_utils.is_user_editor("create")
	verification.is_email_verified

	# payload cannot contain any invalid field
	not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_create)
}

allow if {
	role_utils.is_user_member("create")

	# payload cannot contain any invalid field
	not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_create)

	# members must be email verified
	verification.is_email_verified

	# if user sent _ownerGroups, then all elements listed in the _ownerGroups array
	# must exists in the 'groups' field in token
	not member_has_problem_with_groups

	# caller must be able to see the source list
	can_user_see_source_record
}

#-----------------------------------------------

payload_contains_any_field(fields) if {
	some field
	field = fields[_]
	input.requestPayload[field]
}

member_has_problem_with_groups if {
	input.requestPayload._ownerGroups
	some group
	group = input.requestPayload._ownerGroups[_]
	not group_in_token_groups(group)
}

group_in_token_groups(group) if {
	some i
	token.payload.groups[i] == group
}

member_has_problem_with_groups if {
	input.requestPayload._ownerGroups
	not token.payload.groups[0]
}

#-----------------------------------------------
# Visibility checks (based on findListById policy) applied to input.source
# These mirror the checks in policies.auth.routes.lists.findListById.policy

source_is_active if {
	input.source._validFromDateTime != null
	time.parse_rfc3339_ns(input.source._validFromDateTime) < time.now_ns()
	not source_is_passive
}

source_is_passive if {
	input.source._validUntilDateTime != null
	time.parse_rfc3339_ns(input.source._validUntilDateTime) <= time.now_ns()
}

source_is_public if {
	input.source._visibility == "public"
}

source_is_protected if {
	input.source._visibility == "protected"
}

source_is_private if {
	input.source._visibility == "private"
}

source_is_belong_to_user if {
	some i
	token.payload.sub = input.source._ownerUsers[i]
}

# Only consider group ownership if the user is not a direct owner
source_is_belong_to_users_groups if {
	not source_is_belong_to_user
	some i
	token.payload.groups[i] in input.source._ownerGroups
}

source_is_user_in_viewerUsers if {
	some i
	token.payload.sub = input.source._viewerUsers[i]
}

source_is_user_in_viewerGroups if {
	some i
	token.payload.groups[i] in input.source._viewerGroups
}

# user can see this source record, because it's his record
can_user_see_source_record if {
	source_is_belong_to_user
	source_is_active
}

# user can see this source record, because record belongs to his groups and record is not private
can_user_see_source_record if {
	source_is_belong_to_users_groups
	source_is_active
	not source_is_private # record is either public or protected
}

# user can see this source record, because it is public and active record
can_user_see_source_record if {
	source_is_public
	source_is_active
}

# user can see this source record, because he is in viewerUsers, and record is active
can_user_see_source_record if {
	source_is_user_in_viewerUsers
	source_is_active
}

# user can see this source record, because he is in viewerGroups, and record is active
can_user_see_source_record if {
	source_is_user_in_viewerGroups
	not source_is_private # record is either public or protected
	source_is_active
}
