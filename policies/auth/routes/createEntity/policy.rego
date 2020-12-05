package policies.auth.routes.createEntity

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
    canMembersManageEntities
    input.decodedJwtPayload.email_verified == true
    not member_used_any_invalid_field
}

is_user_member {
	input.decodedJwtPayload.roles[_] == "tarcinapp_member"
}

# editors are always allowed to create new entities
is_user_editor {
    input.decodedJwtPayload.roles[_] == "tarcinapp_editor"
}

# is_user_editor is true if...
is_user_admin {
    input.decodedJwtPayload.roles[_] == "tarcinapp_admin"
}

member_used_any_invalid_field {
    key = invalid_fields_for_members[i]
    _ = input.requestPayload[key]
}

editor_used_any_invalid_field {
	key = invalid_fields_for_editors[i]
    _ = input.requestPayload[key]
}

canMembersManageEntities := true

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
