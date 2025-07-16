package policies.auth.routes.updateAllEntities.policy

import data.policies.util.common.token as token
import data.policies.util.common.verification as verification
import data.policies.util.genericentities.roles as role_utils
import data.policies.fields.genericentities.policy as forbidden_fields

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
    # forbidden fields for update in payload must have same values as original record
    forbidden_fields_for_update_have_same_value_with_original_record
}

allow if {
    role_utils.is_user_editor("update")
    verification.is_email_verified
    # payload cannot contain any field that requestor cannot see or update
    not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_finding)
    # forbidden fields for update in payload must have same values as original record
    forbidden_fields_for_update_have_same_value_with_original_record
}

#-----------------------------------------------

payload_contains_any_field(fields) if {
    some field
    field = fields[_]
    input.requestPayload[field]
}

# Check if forbidden fields for update in payload have same values as original record
forbidden_fields_for_update_have_same_value_with_original_record if {
    count(forbidden_fields_for_update_with_different_values) == 0
}

# Find forbidden fields for update that have different values
forbidden_fields_for_update_with_different_values[field] if {
    field = forbidden_fields.which_fields_forbidden_for_update[_]
    input.requestPayload[field]
    input.originalRecord[field]
    input.requestPayload[field] != input.originalRecord[field]
}