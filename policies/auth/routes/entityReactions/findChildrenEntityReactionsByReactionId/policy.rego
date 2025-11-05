package policies.auth.routes.entityReactions.findChildrenEntityReactionsByReactionId.policy

import data.policies.util.common.originalRecord as original_record
import data.policies.util.common.token as token
import data.policies.util.common.verification as verification
import data.policies.util.entityReactions.roles as role_utils

# By default, deny requests.
default allow := false

#-----------------------------------------------

# Admin users can find children if they can see the parent reaction
#-----------------------------------------------
allow if {
	role_utils.is_user_admin("find")
	verification.is_email_verified
	parent_reaction_can_user_see_this_record
}

#-----------------------------------------------

# Editor users can find children if they can see the parent reaction
#-----------------------------------------------
allow if {
	role_utils.is_user_editor("find")
	verification.is_email_verified
	parent_reaction_can_user_see_this_record
}

#-----------------------------------------------

# Member users can find children if they can see the parent reaction
#-----------------------------------------------
allow if {
	role_utils.is_user_member("find")
	verification.is_email_verified
	parent_reaction_can_user_see_this_record
}

#-----------------------------------------------

# Visitors can find children if the parent reaction is public and active
#-----------------------------------------------
allow if {
	role_utils.is_user_visitor("find")
	verification.is_email_verified
	original_record.is_public
	original_record.is_active
}

#-----------------------------------------------

# Evaluate visibility of the parent reaction using the common originalRecord helpers
# (these operate over input.originalRecord)
# Based on findEntityReactionById logic

# user can see this reaction, because it's his reaction
parent_reaction_can_user_see_this_record if {
	original_record.is_belong_to_user
	not original_record.is_passive
}

# user can see this reaction, because reaction belongs to his groups and reaction is not private
parent_reaction_can_user_see_this_record if {
	original_record.is_belong_to_users_groups
	not original_record.is_passive
	not original_record.is_private
}

# user can see this reaction, because it is public and active record
parent_reaction_can_user_see_this_record if {
	original_record.is_public
	original_record.is_active
}

# user can see this reaction, because he is in viewerUsers, and reaction is active
parent_reaction_can_user_see_this_record if {
	original_record.is_user_in_viewerUsers
	original_record.is_active
}

# user can see this reaction, because he is in viewerGroups, and reaction is active
parent_reaction_can_user_see_this_record if {
	original_record.is_user_in_viewerGroups
	not original_record.is_private
	original_record.is_active
}

#-----------------------------------------------
