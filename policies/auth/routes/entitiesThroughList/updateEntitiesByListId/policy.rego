package policies.auth.routes.entitiesThroughList.updateEntitiesByListId.policy

import data.policies.fields.policy as central_policy
import data.policies.util.common.token as token
import data.policies.util.common.verification as verification
import data.policies.util.entities.roles as role_utils

# By default, deny requests.
default allow := false

# -----------------------------------------------------------------------------
# DYNAMIC FORBIDDEN LISTS
# -----------------------------------------------------------------------------
default forbidden_find_list := []

forbidden_find_list := res if {
	res := central_policy.get_forbidden_fields("entities", "find", null)
}

default forbidden_update_list := []

forbidden_update_list := res if {
	res := central_policy.get_forbidden_fields("entities", "update", null)
}

# Admins and editors are allowed to update entities by list id.
allow if {
	role_utils.is_user_admin("update", input.requestPayload)
	verification.is_email_verified

	# payload cannot contain any field that requestor cannot see or update
	# Avoid negating calls that depend on rule-computed lists twice —
	# instead check positively for existence of any forbidden field in the
	# payload and negate that single predicate. This avoids negation-as-failure
	# ordering issues when the forbidden lists are computed by rules.
	not exists_forbidden_field_in_payload
}

allow if {
	role_utils.is_user_editor("update", input.requestPayload)
	verification.is_email_verified

	# payload cannot contain any field that requestor cannot see or update
	not exists_forbidden_field_in_payload
}

#-----------------------------------------------

# Positive predicate: true if there exists a forbidden field (from either
# find or update forbidden lists) present in the request payload.
exists_forbidden_field_in_payload if {
	some field
	field = forbidden_find_list[_]
	input.requestPayload[field]
}

exists_forbidden_field_in_payload if {
	some field
	field = forbidden_update_list[_]
	input.requestPayload[field]
}
