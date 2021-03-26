package policies.auth.routes.countEntities.policy

import data.policies.util.common.token as token
import data.policies.util.common.verification as verification
import data.policies.util.genericentities.roles as role_utils


# By default, deny requests.
default allow = false
#-----------------------------------------------

# Decide allow if any of the following section is true
#-----------------------------------------------
allow {
	role_utils.is_user_admin("count")
}

allow {
	role_utils.is_user_editor("count")
}

allow {
	role_utils.is_user_member("count")
   	verification.is_email_verified
}

allow {
	role_utils.is_user_visitor("count")
   	verification.is_email_verified
}