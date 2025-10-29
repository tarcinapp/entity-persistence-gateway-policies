
package policies.auth.routes.entitiesThroughList.updateEntitiesByListId.policy

import data.policies.util.common.token as token
import data.policies.util.common.verification as verification
import data.policies.util.entities.roles as role_utils
import data.policies.fields.entities.policy as forbidden_fields

# By default, deny requests.
default allow = false

# Only global/list admins are allowed to update entities by list id. This
# operation updates multiple entities, so editors are not permitted.
allow if {
    role_utils.is_user_admin("update")
    verification.is_email_verified

    # payload cannot contain any field that requestor cannot see or update
    # Avoid negating calls that depend on rule-computed lists twice —
    # instead check positively for existence of any forbidden field in the
    # payload and negate that single predicate. This avoids negation-as-failure
    # ordering issues when the forbidden lists are computed by rules.
    not exists_forbidden_field_in_payload
}

#-----------------------------------------------

# Positive predicate: true if there exists a forbidden field (from either
# find or update forbidden lists) present in the request payload.
exists_forbidden_field_in_payload if {
    some field
    field = forbidden_fields.which_fields_for_finding[_]
    input.requestPayload[field]
}

exists_forbidden_field_in_payload if {
    some field
    field = forbidden_fields.which_fields_for_update[_]
    input.requestPayload[field]
}

which_fields_for_finding = forbidden_fields.which_fields_for_finding
which_fields_for_update = forbidden_fields.which_fields_for_update