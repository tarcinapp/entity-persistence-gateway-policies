package policies.auth.routes.lists.updateAllLists.policy

import data.policies.fields.policy as central_policy
import data.policies.util.common.token as token
import data.policies.util.common.verification as verification
import data.policies.util.lists.roles as role_utils

# By default, deny requests.
default allow := false

# -----------------------------------------------------------------------------
# DYNAMIC FORBIDDEN LISTS
# -----------------------------------------------------------------------------
default forbidden_find_list := []

forbidden_find_list := res if {
	res := central_policy.get_forbidden_fields("lists", "find", null)
}

default forbidden_update_list := []

forbidden_update_list := res if {
	res := central_policy.get_forbidden_fields("lists", "update", null)
}

#-----------------------------------------------

# Decide allow if any of the following section is true
#-----------------------------------------------
allow if {
	role_utils.is_user_admin("update", input.requestPayload)
	verification.is_email_verified

	# payload cannot contain any field that requestor cannot see or update
	not payload_contains_any_field(forbidden_find_list)
	not payload_contains_any_field(forbidden_update_list)
}

allow if {
	role_utils.is_user_editor("update", input.requestPayload)
	verification.is_email_verified

	# payload cannot contain any field that requestor cannot see or update
	not payload_contains_any_field(forbidden_find_list)
	not payload_contains_any_field(forbidden_update_list)
}

#-----------------------------------------------

payload_contains_any_field(fields) if {
	some field
	field = fields[_]
	input.requestPayload[field]
}
