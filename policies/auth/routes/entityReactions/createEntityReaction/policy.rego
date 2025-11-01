package policies.auth.routes.entityReactions.createEntityReaction.policy

import data.policies.fields.entityReactions.policy as forbidden_fields
import data.policies.util.common.array as array
import data.policies.util.common.token as token
import data.policies.util.common.verification as verification
import data.policies.util.entities.roles as entity_role_utils
import data.policies.util.entityReactions.roles as role_utils

# By default, deny requests.
default allow := false

# Decide allow if any of the following section is true
# ----------------------------------------------
allow if {
	role_utils.is_user_admin("create")
	verification.is_email_verified
	not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_create)
	can_admin_see_source_record
}

allow if {
	role_utils.is_user_editor("create")
	verification.is_email_verified
	not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_create)
	can_editor_see_source_record
}

allow if {
	role_utils.is_user_member("create")
	not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_create)
	verification.is_email_verified
	not member_has_problem_with_groups
	can_member_see_source_record
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
# Visibility checks (based on findEntityById policy) applied to input.source
# These mirror the checks in policies.auth.routes.entities.findEntityById.policy

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

# --- Per-role entity visibility checks ---
can_admin_see_source_record if {
	entity_role_utils.is_user_admin("find")
}

can_editor_see_source_record if {
	entity_role_utils.is_user_editor("find")
}

can_member_see_source_record if {
	entity_role_utils.is_user_member("find")
	source_is_public
	source_is_active
}

can_member_see_source_record if {
	entity_role_utils.is_user_member("find")
	source_is_belong_to_user
	source_is_active
}

can_member_see_source_record if {
	entity_role_utils.is_user_member("find")
	source_is_belong_to_users_groups
	source_is_active
	not source_is_private
}

can_member_see_source_record if {
	entity_role_utils.is_user_member("find")
	source_is_user_in_viewerUsers
	source_is_active
}

can_member_see_source_record if {
	entity_role_utils.is_user_member("find")
	source_is_user_in_viewerGroups
	not source_is_private
	source_is_active
}
