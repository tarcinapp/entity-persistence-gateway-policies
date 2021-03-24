package policies.auth.routes.deleteEntityById.policy

import data.policies.util.genericentities.roles as role_utils

# By default, deny requests.
default allow = false
#-----------------------------------------------


# Decide allow if any of the following section is true
#-----------------------------------------------
allow {
	role_utils.is_user_admin("delete")
}