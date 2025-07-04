package policies.auth.routes.createList.policy

import data.policies.util.common.token as token
import data.policies.util.common.array as array
import data.policies.util.common.verification as verification
import data.policies.util.lists.roles as role_utils
import data.policies.fields.lists.policy as forbidden_fields

# By default, deny requests.
default allow = false

# Decide allow if any of the following section is true
# ----------------------------------------------
allow if {
	role_utils.is_user_admin("create")

    verification.is_email_verified

    # payload cannot contain any invalid field
    not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_create)
}

allow if {
	role_utils.is_user_editor("create")

    verification.is_email_verified

    # payload cannot contain any invalid field
    not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_create)
}

allow if {
	role_utils.is_user_member("create")

    # payload cannot contain any invalid field
    not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_create)
    
    # members must be email verified
    verification.is_email_verified

    # if user sent ownerGroups, then all elements listed in the ownerGroups array
    # must exists in the 'groups' field in token
    not member_has_problem_with_groups
}
#-----------------------------------------------

payload_contains_any_field(fields) if {
    some field
    field = fields[_]
    input.requestPayload[field]
}

member_has_problem_with_groups if {
    input.requestPayload["ownerGroups"]
    some group
    group = input.requestPayload["ownerGroups"][_]
    not group_in_token_groups(group)
}

group_in_token_groups(group) if {
    some i
    token.payload.groups[i] == group
}

member_has_problem_with_groups if {
    input.requestPayload["ownerGroups"]
    not token.payload.groups[0]
}

allow if {
    input.httpMethod == "POST"
    input.requestPath == "/lists"
    input.requestPayload != null
    input.requestPayload != {}
    input.requestPayload.name != null
    input.requestPayload.name != ""
    input.requestPayload.description != null
    input.requestPayload.description != ""
    input.requestPayload.visibility != null
    input.requestPayload.visibility != ""
    input.requestPayload.ownerUsers != null
    input.requestPayload.ownerUsers != []
    input.requestPayload.ownerGroups != null
    input.requestPayload.ownerGroups != []
    input.requestPayload.validFromDateTime != null
    input.requestPayload.validFromDateTime != ""
    input.requestPayload.validUntilDateTime != null
    input.requestPayload.validUntilDateTime != ""
    input.requestPayload.validFromDateTime < input.requestPayload.validUntilDateTime
    input.requestPayload.validFromDateTime != null
    input.requestPayload.validFromDateTime != ""
    input.requestPayload.validUntilDateTime == null
    input.requestPayload.validFromDateTime == null
    input.requestPayload.validUntilDateTime != null
    input.requestPayload.validUntilDateTime != ""
    input.requestPayload.validFromDateTime == null
    input.requestPayload.validUntilDateTime == null
    some i
    input.requestPayload.ownerUsers[i] == input.encodedJwt.payload.sub
    some j, k
    input.requestPayload.ownerGroups[j] == input.encodedJwt.payload.groups[k]
}