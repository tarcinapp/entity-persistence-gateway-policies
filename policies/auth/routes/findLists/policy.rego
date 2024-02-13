package policies.auth.routes.findLists.policy

import data.policies.util.common.token as token
import data.policies.util.common.verification as verification
import data.policies.util.lists.roles as role_utils

# By default, deny requests.
default allow = false

#-----------------------------------------------

# Decide allow if any of the following section is true
#-----------------------------------------------
allow {
	role_utils.is_user_admin("find")
	verification.is_email_verified
}

allow {
	role_utils.is_user_editor("find")
	verification.is_email_verified
}

allow {
	role_utils.is_user_member("find")
	verification.is_email_verified
}

allow {
	role_utils.is_user_visitor("find")
	verification.is_email_verified
}

#-----------------------------------------------