package policies.auth.routes.createEntity.policy

import data.policies.util.common.token as token
import data.policies.util.common.array as array
import data.policies.util.common.verification as verification
import data.policies.util.genericentities.roles as role_utils
import data.policies.fields.genericentities.policy as forbidden_fields

# By default, deny requests.
default allow = false

# Decide allow if any of the following section is true
# ----------------------------------------------
allow {
	role_utils.is_user_admin("create")

    # payload cannot contain any invalid field
    not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_create)
}

allow {
	role_utils.is_user_editor("create")

    # payload cannot contain any invalid field
    not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_create)
}

allow {
	role_utils.is_user_member("create")

    # payload cannot contain any invalid field
    not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_create)
    
    # members must be email verified
    token.payload.email_verified == true

    # if user sent ownerGroups, then all elements listed in the ownerGroups array
    # must exists in the 'groups' field in token
    not member_has_problem_with_groups
}
#-----------------------------------------------

payload_contains_any_field(fields) {
    field = fields[_]
    input.requestPayload[field]
}

member_has_problem_with_groups {
    input.requestPayload["ownerGroups"]
    group = input.requestPayload["ownerGroups"][_]
    not array.contains(token.payload.groups, group)
}

member_has_problem_with_groups {
    input.requestPayload["ownerGroups"]
    not token.payload.groups
}