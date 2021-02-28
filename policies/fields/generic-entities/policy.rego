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

default forbiddenFieldsForMembers = ["validFromDateTime", "validUntilDateTime", "visibility"] 
default forbiddenFieldsForVisitors = []

fields = [] {
	is_user_admin
}

fields = [] {
	is_user_editor
}

fields = fields {
	is_user_member

	fields := array.concat(
    	array.concat(
    		["validFromDateTime" | not can_user_see_field("validFromDateTime")], ["validUntilDateTime" | not can_user_see_field("validUntilDateTime")])
        	, ["visibility" | not can_user_see_field("visibility")])
}

# fields = fields {
# 	is_user_visitor
# }

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
	some i
	role = token.payload.roles[i]
    pattern := sprintf(`tarcinapp\.(records|entities)\.fields\.%s\.(find|update|manage)`, [fieldName])
   	regex.match(pattern, role)
}

token = {"payload": payload} {
  [header, payload, signature] := io.jwt.decode(input.encodedJwt)
}