package policies.fields.genericentities.policy


# Define roles
#-----------------------------------------------
administrative_roles := [
    "tarcinapp.admin",
    "tarcinapp.records.find.admin",    
    "tarcinapp.entities.find.admin"
]

editorial_roles := [
    "tarcinapp.editor",
    "tarcinapp.records.find.editor",    
    "tarcinapp.entities.find.editor"
]

member_roles := [
    "tarcinapp.member",
    "tarcinapp.records.find.member",    
    "tarcinapp.entities.find.member"
]

visitor_roles := [
    "tarcinapp.visitor",
    "tarcinapp.records.find.visitor",    
    "tarcinapp.entities.find.visitor"
]

#-----------------------------------------------


# By default, following fields are forbidden for members and visitors
# Those forbidden for members are already forbidden for visitors
default forbiddenFieldsForMembers = ["validFromDateTime", "validUntilDateTime", "visibility"] 
default forbiddenFieldsForVisitors = []

# Prepare forbidden fields for `find` operations
forbiddenFieldsForFind = [] {
	is_user_admin
}

forbiddenFieldsForFind = [] {
	is_user_editor
}

forbiddenFieldsForFind = forbiddenFieldsForFind {
	is_user_member

	# add field to the result fields array if user cannot see the field.
	forbiddenFieldsForFind := [field | not can_user_see_field(forbiddenFieldsForMembers[i]); field := forbiddenFieldsForMembers[i]]
}


forbiddenFieldsForFind = forbiddenFieldsForFind {
	is_user_visitor

	# merge fields for members with fields for visitors
	allFields := array.concat(forbiddenFieldsForMembers, forbiddenFieldsForVisitors)

	# add field to the result fields array if user can see the field.
	forbiddenFieldsForFind := [field | not can_user_see_field(allFields[i]); field := allFields[i]]
}

# Determine user's role
#-----------------------------------------------
is_user_visitor {
	token.payload.roles[_] == visitor_roles[_] 
}

is_user_member {
	token.payload.roles[_] == member_roles[_]
}

is_user_editor {
    token.payload.roles[_] == editorial_roles[_]
}

is_user_admin {
    token.payload.roles[_] == administrative_roles[_]
}
#-----------------------------------------------

can_user_see_field(fieldName) {
	role = token.payload.roles[_]
    pattern := sprintf(`tarcinapp\.(records|entities)\.fields\.%s\.(find|update|manage)`, [fieldName])
   	regex.match(pattern, role)
}

token = {"payload": payload} {
  [header, payload, signature] := io.jwt.decode(input.encodedJwt)
}