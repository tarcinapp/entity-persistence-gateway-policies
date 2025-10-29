package policies.fields.entityReactions.policy

import data.policies.util.common.token as token
import data.policies.util.entityReactions.roles as role_utils
import data.policies.fields.entityReactions.policy.forbiddenFields as forbiddenFields
import data.policies.util.common.array as array

default which_fields_forbidden_for_finding = []
default which_fields_forbidden_for_create = []
default which_fields_forbidden_for_update = []

# admin
which_fields_forbidden_for_finding = which_fields_forbidden_for_finding if {
    role_utils.is_user_admin("find")

    fields := get_effective_fields_for("admin", "find")

    which_fields_forbidden_for_finding := [field | 
        some i
        field := fields[i]
        not can_user_find_field(field)
    ]
}

# If user is admin for update, they should also be treated as admin for find
which_fields_forbidden_for_finding = which_fields_forbidden_for_finding if {
    role_utils.is_user_admin("update")

    fields := get_effective_fields_for("admin", "find")

    which_fields_forbidden_for_finding := [field | 
        some i
        field := fields[i]
        not can_user_find_field(field)
    ]
}

which_fields_forbidden_for_create = which_fields_forbidden_for_create if {
    role_utils.is_user_admin("create")

    fields := get_effective_fields_for("admin", "create")

    which_fields_forbidden_for_create := [field | 
        some i
        field := fields[i]
        not can_user_create_field(field)
    ]
}

which_fields_forbidden_for_update = which_fields_forbidden_for_update if {
    role_utils.is_user_admin("update")

    fields := get_effective_fields_for("admin", "update")

    which_fields_forbidden_for_update := [field | 
        some i
        field := fields[i]
        not can_user_update_field(field)
    ]
}

#editor
which_fields_forbidden_for_finding = which_fields_forbidden_for_finding if {
    role_utils.is_user_editor("find")

    fields := get_effective_fields_for("editor", "find")

    which_fields_forbidden_for_finding := [field | 
        some i
        field := fields[i]
        not can_user_find_field(field)
    ]
}

which_fields_forbidden_for_create = which_fields_forbidden_for_create if {
    role_utils.is_user_editor("create")

    fields := get_effective_fields_for("editor", "create")

    which_fields_forbidden_for_create := [field | 
        some i
        field := fields[i]
        not can_user_create_field(field)
    ]
}

which_fields_forbidden_for_update = which_fields_forbidden_for_update if {
    role_utils.is_user_editor("update")

    fields := get_effective_fields_for("editor", "update")

    which_fields_forbidden_for_update := [field | 
        some i
        field := fields[i]
        not can_user_update_field(field)
    ]
}

#member
which_fields_forbidden_for_finding = which_fields_forbidden_for_finding if {
    role_utils.is_user_member("find")

    fields := get_effective_fields_for("member", "find")

    which_fields_forbidden_for_finding := [field | 
        some i
        field := fields[i]
        not can_user_find_field(field)
    ]
}

which_fields_forbidden_for_create = which_fields_forbidden_for_create if {
    role_utils.is_user_member("create")

    fields := get_effective_fields_for("member", "create")

    which_fields_forbidden_for_create := [field | 
        some i
        field := fields[i]
        not can_user_create_field(field)
    ]
}

which_fields_forbidden_for_update = which_fields_forbidden_for_update if {
    role_utils.is_user_member("update")

    fields := get_effective_fields_for("member", "update")

    which_fields_forbidden_for_update := [field | 
        some i
        field := fields[i]
        not can_user_update_field(field)
    ]
}

#visitor
which_fields_forbidden_for_finding = which_fields_forbidden_for_finding if {
    role_utils.is_user_visitor("find")

    fields := get_effective_fields_for("visitor", "find")

    which_fields_forbidden_for_finding := [field | 
        some i
        field := fields[i]
        not can_user_find_field(field)
    ]
}
#-----------------------------------------------

# this method only selects the field array for given role and operation
get_fields_for(role, operation) = result_fields if {   
    result_fields := [result_field | 
        some i
        forbiddenFields[i].role == role
        forbiddenFields[i].operations[operation]
        some j
        result_field := forbiddenFields[i].operations[operation][j]
    ]
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
    input.appShortcode
    token.payload.roles
    role = token.payload.roles[_]
    pattern := sprintf(`%s\.entityReactions\.fields\.%s\.(find|update|create|manage)`, [input.appShortcode, fieldName])
    regex.match(pattern, role)
}

can_user_create_field(fieldName) if {
    input.appShortcode
    token.payload.roles
    role := token.payload.roles[_]
    pattern := sprintf(`%s\.entityReactions\.fields\.%s\.(create|manage)`, [input.appShortcode, fieldName])
    regex.match(pattern, role)
}

can_user_update_field(fieldName) if {
    input.appShortcode
    token.payload.roles
    role := token.payload.roles[_]
    pattern := sprintf(`%s\.entityReactions\.fields\.%s\.(update|manage)`, [input.appShortcode, fieldName])
    regex.match(pattern, role)
}
