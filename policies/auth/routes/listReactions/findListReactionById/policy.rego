package policies.auth.routes.listReactions.findListReactionById.policy

import data.policies.util.common.originalRecord as original_record
import data.policies.util.common.token as token
import data.policies.util.common.verification as verification
import data.policies.util.listReactions.roles as reaction_roles
import data.policies.util.lists.roles as list_roles

# By default, deny requests.
default allow := false

#-----------------------------------------------

# Admin and editor users for listReactions are always allowed to retrieve the reaction
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

# Members can see list reactions if they can see both the parent list (input.source)
# and the reaction itself (input.originalRecord)
allow if {
	reaction_roles.is_user_member("find")
	verification.is_email_verified
	list_can_user_see_this_record
	reaction_can_user_see_this_record
}

#-----------------------------------------------

# Visitors are allowed to retrieve only active and public reactions when the list
# is also public and active
allow if {
	reaction_roles.is_user_visitor("find")
	verification.is_email_verified
	list_is_public
	list_is_active
	original_record.is_public
	original_record.is_active
}

#-----------------------------------------------

# Evaluate visibility of the parent list provided in input.source

list_is_active if {
	input.source._validFromDateTime != null
	time.parse_rfc3339_ns(input.source._validFromDateTime) < time.now_ns()
	not list_is_passive
}

list_is_passive if {
	input.source._validUntilDateTime != null
	time.parse_rfc3339_ns(input.source._validUntilDateTime) <= time.now_ns()
}

list_is_public if {
	input.source._visibility == "public"
}

list_is_protected if {
	input.source._visibility == "protected"
}

list_is_private if {
	input.source._visibility == "private"
}

list_is_belong_to_user if {
	some i
	token.payload.sub = input.source._ownerUsers[i]
}

# Only consider group ownership if the user is not a direct owner
list_is_belong_to_users_groups if {
	not list_is_belong_to_user
	some i
	token.payload.groups[i] in input.source._ownerGroups
}

list_is_user_in_viewerUsers if {
	some i
	token.payload.sub = input.source._viewerUsers[i]
}

list_is_user_in_viewerGroups if {
	some i
	token.payload.groups[i] in input.source._viewerGroups
}

## Reuse the same visibility/ownership/viewer rules applied for lists
list_can_user_see_this_record if {
	list_is_belong_to_user
	not list_is_passive
}

list_can_user_see_this_record if {
	list_is_belong_to_users_groups
	not list_is_passive
	not list_is_private
}

list_can_user_see_this_record if {
	list_is_public
	list_is_active
}

list_can_user_see_this_record if {
	list_is_user_in_viewerUsers
	list_is_active
}

list_can_user_see_this_record if {
	list_is_user_in_viewerGroups
	not list_is_private
	list_is_active
}

#-----------------------------------------------

# Evaluate visibility of the listReaction using the common originalRecord helpers
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
