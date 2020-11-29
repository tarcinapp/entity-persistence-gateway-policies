#
# This policy evaluates the user's role, email verification status and sent fields to decide if entity creation is allowed.
# - admin users are allowed to create entity no matter the fields they want to create
# - editors users are allowed to create as long as they are not used any of the invalid fields listed in the data. For instance
#   editors cannot send creationDateTime or ownerUsers fields at the time of creation. 
# - members are allowed to create if their email is verified and all fields are valid. For instance, members cannot send visibility
#   field at the time of the creation

package tarcinapp.entity.create

# By default, deny requests.
default allow = false

allow {
	is_user_admin
}

allow {
	is_user_editor
    not editor_used_any_invalid_field
}

# if user is member, then it should satisfy a group of conditions to be allowed for creation
allow {
	is_user_member
    input.email_verified == true
    not member_used_any_invalid_field
}

is_user_member {
	input.user_roles[_] == "tarcinapp_member"
}

# editors are always allowed to create new entities
is_user_editor {
    input.user_roles[_] == "tarcinapp_editor"
}

# is_user_editor is true if...
is_user_admin {
    input.user_roles[i] == "tarcinapp_admin"
}

member_used_any_invalid_field {
	input.fields[_] = data.invalid_fields_for_members[_]
}

editor_used_any_invalid_field {
	input.fields[_] = data.invalid_fields_for_editors[_]
}
