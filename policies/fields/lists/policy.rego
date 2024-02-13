package policies.fields.lists.policy

import data.policies.util.common.token as token
import data.policies.util.lists.roles as role_utils
import data.policies.fields.lists.policy.forbiddenFields as forbiddenFields

# admin
which_fields_forbidden_for_finding = which_fields_forbidden_for_finding {
	role_utils.is_user_admin("find")

    fields := get_effective_fields_for("admin", "find")

    which_fields_forbidden_for_finding := [field | not can_user_find_field(fields[i]); field := fields[i]]
}

which_fields_forbidden_for_create = which_fields_forbidden_for_create {
	role_utils.is_user_admin("create")

    fields := get_effective_fields_for("admin", "create")

    which_fields_forbidden_for_create := [field | not can_user_create_field(fields[i]); field := fields[i]]
}

which_fields_forbidden_for_update = which_fields_forbidden_for_update {
	role_utils.is_user_admin("update")

    fields := get_effective_fields_for("admin", "update")

    which_fields_forbidden_for_update := [field | not can_user_update_field(fields[i]); field := fields[i]]
}

#editor
which_fields_forbidden_for_finding = which_fields_forbidden_for_finding {
	role_utils.is_user_editor("find")

    fields := get_effective_fields_for("editor", "find")

    which_fields_forbidden_for_finding := [field | not can_user_find_field(fields[i]); field := fields[i]]
}

which_fields_forbidden_for_create = which_fields_forbidden_for_create {
	role_utils.is_user_editor("create")

    fields := get_effective_fields_for("editor", "create")

    which_fields_forbidden_for_create := [field | not can_user_create_field(fields[i]); field := fields[i]]
}

which_fields_forbidden_for_update = which_fields_forbidden_for_update {
	role_utils.is_user_editor("update")

    fields := get_effective_fields_for("editor", "update")

    which_fields_forbidden_for_update := [field | not can_user_update_field(fields[i]); field := fields[i]]
}

#member
which_fields_forbidden_for_finding = which_fields_forbidden_for_finding {
	role_utils.is_user_member("find")

    fields := get_effective_fields_for("member", "find")

    which_fields_forbidden_for_finding := [field | not can_user_find_field(fields[i]); field := fields[i]]
}

which_fields_forbidden_for_create = which_fields_forbidden_for_create {
	role_utils.is_user_member("create")

    fields := get_effective_fields_for("member", "create")

    which_fields_forbidden_for_create := [field | not can_user_create_field(fields[i]); field := fields[i]]
}

which_fields_forbidden_for_update = which_fields_forbidden_for_update {
	role_utils.is_user_member("update")

    fields := get_effective_fields_for("member", "update")

    which_fields_forbidden_for_update := [field | not can_user_update_field(fields[i]); field := fields[i]]
}

#visitor
which_fields_forbidden_for_finding = which_fields_forbidden_for_finding {
	role_utils.is_user_visitor("find")

    fields := get_effective_fields_for("visitor", "find")

    which_fields_forbidden_for_finding := [field | not can_user_find_field(fields[i]); field := fields[i]]
}
#-----------------------------------------------

# this method only selects the field array for given role and operation
get_fields_for(role, operation) = result_fields {   
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
get_effective_fields_for(role, operation) = result_fields {
    operation == "find"
    result_fields := get_fields_for(role, "find")
}

get_effective_fields_for(role, operation) = result_fields {
    operation == "create"
    fields_for_find := get_fields_for(role, "find")
    fields_for_create := get_fields_for(role, "create")
    result_fields := array.concat(fields_for_find, fields_for_create)
}

get_effective_fields_for(role, operation) = result_fields {
    operation == "update"
    fields_for_find := get_fields_for(role, "find")
    fields_for_update := get_fields_for(role, "update")
    result_fields := array.concat(fields_for_find, fields_for_update)
}

can_user_find_field(fieldName) {
	role = token.payload.roles[_]
	pattern := sprintf(`%s\.(records|lists)\.fields\.%s\.(find|update|create|manage)`, [input.appShortcode, fieldName])
	regex.match(pattern, role)
}

can_user_create_field(fieldName) {
	role := token.payload.roles[_]
	pattern := sprintf(`%s\.(records|lists)\.fields\.%s\.(create|manage)`, [input.appShortcode, fieldName])
	regex.match(pattern, role)
}

can_user_update_field(fieldName) {
	role := token.payload.roles[_]
	pattern := sprintf(`%s\.(records|lists)\.fields\.%s\.(update|manage)`, [input.appShortcode, fieldName])
	regex.match(pattern, role)
}
