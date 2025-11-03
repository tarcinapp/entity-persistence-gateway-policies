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
# Visibility checks (based on findEntityById policy) applied to input.requestPayload._relationMetadata
# These mirror the checks in policies.auth.routes.entities.findEntityById.policy

related_entity_is_active if {
	input.requestPayload._relationMetadata._validFromDateTime != null
	time.parse_rfc3339_ns(input.requestPayload._relationMetadata._validFromDateTime) < time.now_ns()
	not related_entity_is_passive
}

related_entity_is_passive if {
	input.requestPayload._relationMetadata._validUntilDateTime != null
	time.parse_rfc3339_ns(input.requestPayload._relationMetadata._validUntilDateTime) <= time.now_ns()
}

related_entity_is_public if {
	input.requestPayload._relationMetadata._visibility == "public"
}

related_entity_is_protected if {
	input.requestPayload._relationMetadata._visibility == "protected"
}

related_entity_is_private if {
	input.requestPayload._relationMetadata._visibility == "private"
}

related_entity_is_belong_to_user if {
	some i
	token.payload.sub = input.requestPayload._relationMetadata._ownerUsers[i]
}

# Only consider group ownership if the user is not a direct owner
related_entity_is_belong_to_users_groups if {
	not related_entity_is_belong_to_user
	some i
	token.payload.groups[i] in input.requestPayload._relationMetadata._ownerGroups
}

related_entity_is_user_in_viewerUsers if {
	some i
	token.payload.sub = input.requestPayload._relationMetadata._viewerUsers[i]
}

related_entity_is_user_in_viewerGroups if {
	some i
	token.payload.groups[i] in input.requestPayload._relationMetadata._viewerGroups
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
	related_entity_is_public
	related_entity_is_active
}

can_member_see_source_record if {
	entity_role_utils.is_user_member("find")
	related_entity_is_belong_to_user
	related_entity_is_active
}

can_member_see_source_record if {
	entity_role_utils.is_user_member("find")
	related_entity_is_belong_to_users_groups
	related_entity_is_active
	not related_entity_is_private
}

can_member_see_source_record if {
	entity_role_utils.is_user_member("find")
	related_entity_is_user_in_viewerUsers
	related_entity_is_active
}

can_member_see_source_record if {
	entity_role_utils.is_user_member("find")
	related_entity_is_user_in_viewerGroups
	not related_entity_is_private
	related_entity_is_active
}
