package policies.auth.routes.deleteEntityById.policy

import data.policies.util.genericentities.roles as role_utils

# By default, deny requests.
default allow = false
#-----------------------------------------------

allow {
	role_utils.is_user_admin("delete")
}