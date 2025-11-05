package policies.auth.routes.reactionsThroughList.findReactionsByListId.policy

import data.policies.util.common.token as token
import data.policies.util.common.verification as verification
import data.policies.util.listReactions.roles as reaction_role_utils
import data.policies.util.lists.roles as list_role_utils

# By default, deny requests.
default allow := false

#-----------------------------------------------

# Admin users can find reactions if they can find list reactions
#-----------------------------------------------
allow if {
	reaction_role_utils.is_user_admin("find")
	verification.is_email_verified
}

#-----------------------------------------------

# Editor users can find reactions if they can find list reactions
#-----------------------------------------------
allow if {
	reaction_role_utils.is_user_editor("find")
	verification.is_email_verified
}

#-----------------------------------------------

# Member users can find reactions if they can find list reactions
#-----------------------------------------------
allow if {
	reaction_role_utils.is_user_member("find")
	verification.is_email_verified
}

#-----------------------------------------------

# Visitor users can find reactions if they can find list reactions
#-----------------------------------------------
allow if {
	reaction_role_utils.is_user_visitor("find")
	verification.is_email_verified
}

#-----------------------------------------------
