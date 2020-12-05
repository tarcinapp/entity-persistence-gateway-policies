package policies.auth.routes.createEntity.policy

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
    input.decodedJwtPayload.email_verified == true
    not member_used_any_invalid_field
}

is_user_member {
	input.decodedJwtPayload.roles[_] == member_roles[_]
}

# editors are always allowed to create new entities
is_user_editor {
    input.decodedJwtPayload.roles[_] == editorial_roles[_]
}

# is_user_editor is true if...
is_user_admin {
    input.decodedJwtPayload.roles[_] == administrative_roles[_]
}

member_used_any_invalid_field {
    key = invalid_fields_for_members[i]
    _ = input.requestPayload[key]
}

editor_used_any_invalid_field {
	key = invalid_fields_for_editors[i]
    _ = input.requestPayload[key]
}

administrative_roles := [
	"tarcinapp_admin",
    "tarcinapp.admin",
    "tarcinapp.manage.admin",
    "tarcinapp.create.admin",
    "tarcinapp.entities.manage.admin",
    "tarcinapp.entities.create.admin"
]

editorial_roles := [
	"tarcinapp_editor",
    "tarcinapp.editor",
    "tarcinapp.manage.editor",
    "tarcinapp.create.editor",
    "tarcinapp.entities.manage.editor",
    "tarcinapp.entities.create.editor"
]

member_roles := [
	"tarcinapp_member",
    "tarcinapp.member",
    "tarcinapp.manage.member",
    "tarcinapp.create.member",
    "tarcinapp.entities.manage.member",
    "tarcinapp.entities.create.member"
]

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
