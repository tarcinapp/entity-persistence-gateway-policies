package policies.auth.routes.listReactions.createChildListReaction.policy

import data.policies.fields.listReactions.policy as forbidden_fields
import data.policies.util.common.originalRecord as original_record
import data.policies.util.common.token as token
import data.policies.util.common.verification as verification
import data.policies.util.listReactions.roles as reaction_roles
import data.policies.util.lists.roles as list_roles

# By default, deny requests.
default allow := false

#-----------------------------------------------

# Admin users can create child list reactions if they can see the parent reaction and the related list
#-----------------------------------------------
allow if {
	reaction_roles.is_user_admin("create")
	verification.is_email_verified
	not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_create)
	can_user_see_parent_reaction
	can_user_see_related_list
}

#-----------------------------------------------

# Editor users can create child list reactions if they can see the parent reaction and the related list
#-----------------------------------------------
allow if {
	reaction_roles.is_user_editor("create")
	verification.is_email_verified
	not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_create)
	can_user_see_parent_reaction
	can_user_see_related_list
}

#-----------------------------------------------

# Member users can create child list reactions if they can see both the parent reaction and the related list
#-----------------------------------------------
allow if {
	reaction_roles.is_user_member("create")
	verification.is_email_verified
	not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_create)
	not member_has_problem_with_groups
	can_user_see_parent_reaction
	can_user_see_related_list
}

#-----------------------------------------------

# Payload validation helpers
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

# Parent list reaction visibility checks (using input.originalRecord)
# Based on findListReactionById logic
#-----------------------------------------------

can_user_see_parent_reaction if {
	reaction_roles.is_user_admin("find")
}

can_user_see_parent_reaction if {
	reaction_roles.is_user_editor("find")
}

can_user_see_parent_reaction if {
	reaction_roles.is_user_member("find")
	parent_reaction_is_active_and_visible_to_member
}

can_user_see_parent_reaction if {
	reaction_roles.is_user_visitor("find")
	original_record.is_public
	original_record.is_active
}

#-----------------------------------------------

# Parent reaction visibility rules for member creation (must be ACTIVE)
#-----------------------------------------------

# For member creation, parent reaction must be ACTIVE (pending is not allowed)
parent_reaction_is_active_and_visible_to_member if {
	original_record.is_active
	original_record.is_belong_to_user
}

parent_reaction_is_active_and_visible_to_member if {
	original_record.is_active
	original_record.is_belong_to_users_groups
	not original_record.is_private
}

parent_reaction_is_active_and_visible_to_member if {
	original_record.is_active
	original_record.is_public
}

parent_reaction_is_active_and_visible_to_member if {
	original_record.is_active
	original_record.is_user_in_viewerUsers
}

parent_reaction_is_active_and_visible_to_member if {
	original_record.is_active
	original_record.is_user_in_viewerGroups
	not original_record.is_private
}

#-----------------------------------------------

# Related list visibility checks (using input.originalRecord._relationMetadata)
# Based on findListReactionById and findListById logic
#-----------------------------------------------

can_user_see_related_list if {
	list_roles.is_user_admin("find")
}

can_user_see_related_list if {
	list_roles.is_user_editor("find")
}

can_user_see_related_list if {
	list_roles.is_user_member("find")
	list_is_active_and_visible_to_member
}

#-----------------------------------------------

# Related list visibility rules (input.originalRecord._relationMetadata)
#-----------------------------------------------

list_is_active if {
	input.originalRecord._relationMetadata._validFromDateTime != null
	time.parse_rfc3339_ns(input.originalRecord._relationMetadata._validFromDateTime) < time.now_ns()
	not list_is_passive
}

list_is_passive if {
	input.originalRecord._relationMetadata._validUntilDateTime != null
	time.parse_rfc3339_ns(input.originalRecord._relationMetadata._validUntilDateTime) <= time.now_ns()
}

list_is_public if {
	input.originalRecord._relationMetadata._visibility == "public"
}

list_is_protected if {
	input.originalRecord._relationMetadata._visibility == "protected"
}

list_is_private if {
	input.originalRecord._relationMetadata._visibility == "private"
}

list_is_belong_to_user if {
	some i
	token.payload.sub = input.originalRecord._relationMetadata._ownerUsers[i]
}

list_is_belong_to_users_groups if {
	not list_is_belong_to_user
	some i
	token.payload.groups[i] in input.originalRecord._relationMetadata._ownerGroups
}

list_is_user_in_viewerUsers if {
	some i
	token.payload.sub = input.originalRecord._relationMetadata._viewerUsers[i]
}

list_is_user_in_viewerGroups if {
	some i
	token.payload.groups[i] in input.originalRecord._relationMetadata._viewerGroups
}

# Related list visibility rules for member creation (must be ACTIVE)
#-----------------------------------------------

# For member creation, related list must be ACTIVE (pending is not allowed)
list_is_active_and_visible_to_member if {
	list_is_active
	list_is_belong_to_user
}

list_is_active_and_visible_to_member if {
	list_is_active
	list_is_belong_to_users_groups
	not list_is_private
}

list_is_active_and_visible_to_member if {
	list_is_active
	list_is_public
}

list_is_active_and_visible_to_member if {
	list_is_active
	list_is_user_in_viewerUsers
}

list_is_active_and_visible_to_member if {
	list_is_active
	list_is_user_in_viewerGroups
	not list_is_private
}
