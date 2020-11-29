package auth.createEntity.policy

# By default, deny requests.
default allow = false

allow {
	is_user_admin
}

allow {
	is_user_editor
    not editor_used_any_invalid_field
}

# if user is a member, then it should satisfy a group of conditions to be allowed for creation
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
	input.fields[_] = invalid_fields_for_members[_]
}

editor_used_any_invalid_field {
	input.fields[_] = invalid_fields_for_editors[_]
}

invalid_fields_for_members := [
        "creationDateTime",
        "visibility",
        "validFromDateTime",
        "validUntilDateTime",
        "ownerUsers",
        "ownerGroups"
]

invalid_fields_for_editors := [
	"creationDateTime",
	"ownerUsers",
	"ownerGroups"
]
