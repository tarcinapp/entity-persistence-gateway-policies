package policies.fields.lists.policy

import data.policies.util.common.token as token
import data.policies.util.lists.roles as role_utils
import data.policies.fields.lists.policy.forbiddenFields as forbiddenFields
import data.policies.util.common.array as array

# admin
which_fields_forbidden_for_finding = which_fields_forbidden_for_finding if {
	role_utils.is_user_admin("find")

    fields := get_effective_fields_for("admin", "find")

    which_fields_forbidden_for_finding := [field | not can_user_find_field(fields[i]); field := fields[i]]
}

which_fields_forbidden_for_create if {
    not is_user_admin
    not is_user_editor
    not is_user_member
    not is_user_visitor
}

which_fields_forbidden_for_update if {
    not is_user_admin
    not is_user_editor
    not is_user_member
    not is_user_visitor
}

#editor
which_fields_forbidden_for_finding = which_fields_forbidden_for_finding if {
	role_utils.is_user_editor("find")

    fields := get_effective_fields_for("editor", "find")

    which_fields_forbidden_for_finding := [field | not can_user_find_field(fields[i]); field := fields[i]]
}

which_fields_forbidden_for_create if {
    is_user_admin
    not is_user_editor
    not is_user_member
    not is_user_visitor
}

which_fields_forbidden_for_update if {
    is_user_admin
    is_user_editor
    not is_user_member
    not is_user_visitor
}

#member
which_fields_forbidden_for_finding = which_fields_forbidden_for_finding if {
	role_utils.is_user_member("find")

    fields := get_effective_fields_for("member", "find")

    which_fields_forbidden_for_finding := [field | not can_user_find_field(fields[i]); field := fields[i]]
}

which_fields_forbidden_for_create if {
    is_user_admin
    is_user_editor
    is_user_member
    not is_user_visitor
}

which_fields_forbidden_for_update if {
    is_user_admin
    is_user_editor
    is_user_member
    is_user_visitor
}

#visitor
which_fields_forbidden_for_finding = which_fields_forbidden_for_finding if {
	role_utils.is_user_visitor("find")

    fields := get_effective_fields_for("visitor", "find")

    which_fields_forbidden_for_finding := [field | not can_user_find_field(fields[i]); field := fields[i]]
}
#-----------------------------------------------

# this method only selects the field array for given role and operation
get_fields_for(role, operation) = result_fields if {   
    result_fields := [result_field | forbiddenFields[i].role==role; result_field := forbiddenFields[i].operations[operation]][0]
}

# We need this operation in order to get merged list of fields for different operations.
# For instance, if caller asks for effective list of forbidden fields for 'create' operation, this method gets
# list of fields for 'create' and 'find' operations and merges these two list. 
#
# Same logic applies to 'update' operation as well. If caller asks for effective fields for 'update' operation
# this method merges the lists for both 'update' and 'find', and returns the list.
#
# If caller asks for effective list of forbidden fields for 'find' operation, this method simply returns
# the fields list of 'find' operation, without performing any logic.
get_effective_fields_for(role, operation) = result_fields if {
    operation == "find"
    result_fields := get_fields_for(role, "find")
}

get_effective_fields_for(role, operation) = result_fields if {
    operation == "create"
    fields_for_find := get_fields_for(role, "find")
    fields_for_create := get_fields_for(role, "create")
    result_fields := array.concat(fields_for_find, fields_for_create)
}

get_effective_fields_for(role, operation) = result_fields if {
    operation == "update"
    fields_for_find := get_fields_for(role, "find")
    fields_for_update := get_fields_for(role, "update")
    result_fields := array.concat(fields_for_find, fields_for_update)
}

can_user_find_field(fieldName) if {
	role = token.payload.roles[_]
	pattern := sprintf(`%s\.(records|lists)\.fields\.%s\.(find|update|create|manage)`, [input.appShortcode, fieldName])
	regex.match(pattern, role)
}

can_user_create_field(fieldName) if {
	role := token.payload.roles[_]
	pattern := sprintf(`%s\.(records|lists)\.fields\.%s\.(create|manage)`, [input.appShortcode, fieldName])
	regex.match(pattern, role)
}

can_user_update_field(fieldName) if {
	role := token.payload.roles[_]
	pattern := sprintf(`%s\.(records|lists)\.fields\.%s\.(update|manage)`, [input.appShortcode, fieldName])
	regex.match(pattern, role)
}

is_user_admin if {
    role_utils.is_user_admin("create")
}

is_user_editor if {
    role_utils.is_user_editor("create")
}

is_user_member if {
    role_utils.is_user_member("create")
}

is_user_visitor if {
    role_utils.is_user_visitor("create")
}

allow if {
    input.httpMethod == "POST"
    input.requestPath == "/lists"
    input.requestPayload.name != null
    input.requestPayload.name != ""
}

allow if {
    input.httpMethod == "POST"
    input.requestPath == "/lists"
    input.requestPayload.description != null
    input.requestPayload.description != ""
}

allow if {
    input.httpMethod == "POST"
    input.requestPath == "/lists"
    input.requestPayload.visibility != null
    input.requestPayload.visibility != ""
}

allow if {
    input.httpMethod == "POST"
    input.requestPath == "/lists"
    input.requestPayload.ownerUsers != null
    input.requestPayload.ownerUsers != []
}

allow if {
    input.httpMethod == "POST"
    input.requestPath == "/lists"
    input.requestPayload.ownerGroups != null
    input.requestPayload.ownerGroups != []
}

allow if {
    input.httpMethod == "POST"
    input.requestPath == "/lists"
    input.requestPayload.validFromDateTime != null
    input.requestPayload.validFromDateTime != ""
}

allow if {
    input.httpMethod == "POST"
    input.requestPath == "/lists"
    input.requestPayload.validUntilDateTime != null
    input.requestPayload.validUntilDateTime != ""
}

allow if {
    input.httpMethod == "POST"
    input.requestPath == "/lists"
    input.requestPayload.validFromDateTime != null
    input.requestPayload.validFromDateTime != ""
    input.requestPayload.validUntilDateTime != null
    input.requestPayload.validUntilDateTime != ""
    input.requestPayload.validFromDateTime < input.requestPayload.validUntilDateTime
}

allow if {
    input.httpMethod == "POST"
    input.requestPath == "/lists"
    input.requestPayload.validFromDateTime != null
    input.requestPayload.validFromDateTime != ""
    input.requestPayload.validUntilDateTime == null
}

allow if {
    input.httpMethod == "POST"
    input.requestPath == "/lists"
    input.requestPayload.validFromDateTime == null
    input.requestPayload.validUntilDateTime != null
    input.requestPayload.validUntilDateTime != ""
}

allow if {
    input.httpMethod == "POST"
    input.requestPath == "/lists"
    input.requestPayload.validFromDateTime == null
    input.requestPayload.validUntilDateTime == null
}
