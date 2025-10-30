package policies.auth.routes.entityReactions.findEntityReactionById.policy

import data.policies.util.common.originalRecord as original_record
import data.policies.util.common.token as token
import data.policies.util.common.verification as verification
import data.policies.util.entities.roles as entity_roles
import data.policies.util.entityReactions.roles as reaction_roles

# By default, deny requests.
default allow := false

#-----------------------------------------------

# Admin and editor users for entityReactions are always allowed to retrieve the reaction
#-----------------------------------------------
allow if {
	reaction_roles.is_user_admin("find")
	verification.is_email_verified
}

allow if {
	reaction_roles.is_user_editor("find")
	verification.is_email_verified
}

#-----------------------------------------------

# Members can see reactions if they can see both the parent entity (input.source)
# and the reaction itself (input.originalRecord)
allow if {
	reaction_roles.is_user_member("find")
	verification.is_email_verified
	entity_can_user_see_this_record
	reaction_can_user_see_this_record
}

#-----------------------------------------------

# Visitors are allowed to retrieve only active and public reactions when the entity
# is also public and active
allow if {
	reaction_roles.is_user_visitor("find")
	verification.is_email_verified
	entity_is_public
	entity_is_active
	original_record.is_public
	original_record.is_active
}

#-----------------------------------------------

# Evaluate visibility of the parent entity provided in input.source

entity_is_active if {
	input.source._validFromDateTime != null
	time.parse_rfc3339_ns(input.source._validFromDateTime) < time.now_ns()
	not entity_is_passive
}

entity_is_passive if {
	input.source._validUntilDateTime != null
	time.parse_rfc3339_ns(input.source._validUntilDateTime) <= time.now_ns()
}

entity_is_public if {
	input.source._visibility == "public"
}

entity_is_protected if {
	input.source._visibility == "protected"
}

entity_is_private if {
	input.source._visibility == "private"
}

entity_is_belong_to_user if {
	some i
	token.payload.sub = input.source._ownerUsers[i]
}

# Only consider group ownership if the user is not a direct owner
entity_is_belong_to_users_groups if {
	not entity_is_belong_to_user
	some i
	token.payload.groups[i] in input.source._ownerGroups
}

entity_is_user_in_viewerUsers if {
	some i
	token.payload.sub = input.source._viewerUsers[i]
}

entity_is_user_in_viewerGroups if {
	some i
	token.payload.groups[i] in input.source._viewerGroups
}

## Reuse the same visibility/ownership/viewer rules applied for entities
entity_can_user_see_this_record if {
	entity_is_belong_to_user
	not entity_is_passive
}

entity_can_user_see_this_record if {
	entity_is_belong_to_users_groups
	not entity_is_passive
	not entity_is_private
}

entity_can_user_see_this_record if {
	entity_is_public
	entity_is_active
}

entity_can_user_see_this_record if {
	entity_is_user_in_viewerUsers
	entity_is_active
}

entity_can_user_see_this_record if {
	entity_is_user_in_viewerGroups
	not entity_is_private
	entity_is_active
}

#-----------------------------------------------

# Evaluate visibility of the entityReaction using the common originalRecord helpers
# (these operate over input.originalRecord)

# user can see this reaction, because it's his reaction
reaction_can_user_see_this_record if {
	original_record.is_belong_to_user
	not original_record.is_passive
}

# user can see this reaction, because reaction belongs to his groups and reaction is not private
reaction_can_user_see_this_record if {
	original_record.is_belong_to_users_groups
	not original_record.is_passive
	not original_record.is_private
}

# user can see this reaction, because it is public and active record
reaction_can_user_see_this_record if {
	original_record.is_public
	original_record.is_active
}

# user can see this reaction, because he is in viewerUsers, and reaction is active
reaction_can_user_see_this_record if {
	original_record.is_user_in_viewerUsers
	original_record.is_active
}

# user can see this reaction, because he is in viewerGroups, and reaction is active
reaction_can_user_see_this_record if {
	original_record.is_user_in_viewerGroups
	not original_record.is_private
	original_record.is_active
}

#-----------------------------------------------
