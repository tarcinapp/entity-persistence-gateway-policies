package policies.auth.routes.updateAllLists.policy

import data.policies.util.common.token as token
import data.policies.util.common.verification as verification
import data.policies.util.lists.roles as role_utils
import data.policies.fields.lists.policy as forbidden_fields

# By default, deny requests.
default allow = false

#-----------------------------------------------

# Decide allow if any of the following section is true
#-----------------------------------------------
allow if {
    role_utils.is_user_admin("update")
    verification.is_email_verified
    # payload cannot contain any field that requestor cannot see or update
    not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_finding)
    not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_update)
}

allow if {
    role_utils.is_user_editor("update")
    verification.is_email_verified
    # payload cannot contain any field that requestor cannot see or update
    not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_finding)
    not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_update)
}

#-----------------------------------------------

payload_contains_any_field(fields) if {
    some field
    field = fields[_]
    input.requestPayload[field]
}