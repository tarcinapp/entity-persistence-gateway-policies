package policies.fields.genericentities.policy

import data.policies.util.common.token as token
import data.policies.util.genericentities.roles as role_utils

# admins are allowed to see and manage all fields by definition
default forbiddenFields = [
    {
        "role": "admin",
        "operations": {
            "find":   [],
            "create": [],
            "update": []
        }
    },
    {
        "role": "editor",
        "operations": {
            "find":   [],
            "create": ["creationDateTime", "lastUpdatedDateTime", "lastUpdatedBy", "createdBy"],
            "update": ["creationDateTime", "lastUpdatedDateTime", "lastUpdatedBy", "createdBy"],
        }
    },
    {
        "role": "member",
        "operations": {
            "find":   ["visibility"],
            "create": ["creationDateTime", "lastUpdatedDateTime", "lastUpdatedBy", "createdBy", "validFromDateTime", "validUntilDateTime", "ownerUsers"],
            "update": ["kind", "creationDateTime", "lastUpdatedDateTime", "lastUpdatedBy", "createdBy", "validFromDateTime"]
        }
    },
    {
        "role": "visitor",
        "operations": {
            "find": ["validFromDateTime", "validUntilDateTime", "visibility", "lastUpdatedBy", "lastUpdatedDateTime"],
        }
    }
]

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
	pattern := sprintf(`tarcinapp\.(records|entities)\.fields\.%s\.(find|update|manage)`, [fieldName])
	regex.match(pattern, role)
}

can_user_create_field(fieldName) {
	role := token.payload.roles[_]
	pattern := sprintf(`tarcinapp\.(records|entities)\.fields\.%s\.(create|manage)`, [fieldName])
	regex.match(pattern, role)
}

can_user_update_field(fieldName) {
	role := token.payload.roles[_]
	pattern := sprintf(`tarcinapp\.(records|entities)\.fields\.%s\.(update|manage)`, [fieldName])
	regex.match(pattern, role)
}
