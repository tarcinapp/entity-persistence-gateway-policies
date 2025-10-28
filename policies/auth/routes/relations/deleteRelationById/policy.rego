package policies.auth.routes.relations.deleteRelationById.policy

import data.policies.util.common.token as token
import data.policies.util.common.verification as verification
import data.policies.util.relations.roles as role_utils

# By default, deny requests.
default allow = false

#-----------------------------------------------

# Decide allow if any of the following section is true
#-----------------------------------------------
allow if {
	role_utils.is_user_admin("delete")
	verification.is_email_verified
}


#-----------------------------------------------
