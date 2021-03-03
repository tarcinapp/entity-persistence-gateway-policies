package policies.fields.genericentities.policy

#-----------------------------------------------


# By default, following fields are forbidden for members and visitors
# Those forbidden for members are already forbidden for visitors
default forbiddenFieldsForMembers = ["validFromDateTime", "validUntilDateTime", "visibility"] 
default forbiddenFieldsForVisitors = []

# Prepare forbidden fields for `find` operations
forbiddenFields_find = [] {
	is_user_admin("find")
}

forbiddenFields_find = [] {
	is_user_editor("find")
}

forbiddenFields_find = forbiddenFields_find {
	is_user_member("find")

	# add field to the result fields array if user cannot see the field.
	forbiddenFields_find := [field | not can_user_find_field(forbiddenFieldsForMembers[i]); field := forbiddenFieldsForMembers[i]]
}


forbiddenFields_find = forbiddenFields_find {
	is_user_visitor("find")

	# merge fields for members with fields for visitors
	allFields := array.concat(forbiddenFieldsForMembers, forbiddenFieldsForVisitors)

	# add field to the result fields array if user can see the field.
	forbiddenFields_find := [field | not can_user_find_field(allFields[i]); field := allFields[i]]
}

#-----------------------------------------------

can_user_find_field(fieldName) {
	role = token.payload.roles[_]
    pattern := sprintf(`tarcinapp\.(records|entities)\.fields\.%s\.(find|update|manage)`, [fieldName])
   	regex.match(pattern, role)
}

can_user_update_field(fieldName) {
	role = token.payload.roles[_]
    pattern := sprintf(`tarcinapp\.(records|entities)\.fields\.%s\.(update|manage)`, [fieldName])
   	regex.match(pattern, role)
}

can_user_manage_field(fieldName) {
	role = token.payload.roles[_]
    pattern := sprintf(`tarcinapp\.(records|entities)\.fields\.%s\.(manage)`, [fieldName])
   	regex.match(pattern, role)
}

is_user_admin(operationType) {
    role = token.payload.roles[_]
    pattern := sprintf(`tarcinapp(((\.)|(\.(records|entities))|(\.(records|entities)(\.%s)))?)\.admin`, [operationType])
    regex.match(pattern, role)
}

is_user_editor(operationType) {
    role = token.payload.roles[_]
    pattern := sprintf(`tarcinapp(((\.)|(\.(records|entities))|(\.(records|entities)(\.%s)))?)\.editor`, [operationType])
    regex.match(pattern, role)
}

is_user_member(operationType) {
    role = token.payload.roles[_]
    pattern := sprintf(`tarcinapp(((\.)|(\.(records|entities))|(\.(records|entities)(\.%s)))?)\.member`, [operationType])
    regex.match(pattern, role)
}

is_user_visitor(operationType) {
    role = token.payload.roles[_]
    pattern := sprintf(`tarcinapp(((\.)|(\.(records|entities))|(\.(records|entities)(\.%s)))?)\.visitor`, [operationType])
    regex.match(pattern, role)
}

token = {"payload": payload} {
  [header, payload, signature] := io.jwt.decode(input.encodedJwt)
}