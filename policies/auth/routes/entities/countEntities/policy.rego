package policies.auth.routes.entities.countEntities.policy

import data.policies.util.common.token as token
import data.policies.util.common.verification as verification
import data.policies.util.entities.roles as role_utils


# By default, deny requests.
default allow = false
#-----------------------------------------------

# Decide allow if any of the following section is true
#-----------------------------------------------
allow if {
	role_utils.is_user_admin("count")
	verification.is_email_verified
}

allow if {
	role_utils.is_user_editor("count")
	verification.is_email_verified
}

allow if {
	role_utils.is_user_member("count")
   	verification.is_email_verified
}

allow if {
	role_utils.is_user_visitor("count")
   	verification.is_email_verified
}