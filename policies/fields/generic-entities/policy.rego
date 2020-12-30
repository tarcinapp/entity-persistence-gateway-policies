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

user_roles_for_visibility := [
	"tarcinapp.records.fields.visibility.manage",
	"tarcinapp.entities.fields.visibility.manage",
    "tarcinapp.records.fields.visibility.find",
	"tarcinapp.entities.fields.visibility.find",
    "tarcinapp.records.fields.visibility.update",
	"tarcinapp.entities.fields.visibility.update"
]

user_roles_for_validFrom := [
	"tarcinapp.records.fields.validFrom.manage",
	"tarcinapp.entities.fields.validFrom.manage",
    "tarcinapp.records.fields.validFrom.find",
	"tarcinapp.entities.fields.validFrom.find",
    "tarcinapp.records.fields.validFrom.update",
	"tarcinapp.entities.fields.validFrom.update"
]

user_roles_for_validUntil:= [
	"tarcinapp.records.fields.validUntil.manage",
	"tarcinapp.entities.fields.validUntil.manage",
    "tarcinapp.records.fields.validUntil.find",
	"tarcinapp.entities.fields.validUntil.find",
    "tarcinapp.records.fields.validUntil.update",
	"tarcinapp.entities.fields.validUntil.update"
]

#-----------------------------------------------


# By default, following fields are forbidden
default fields = ["validFromDateTime", "validUntilDateTime", "visibility"] 

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
    		["validFromDateTime" | not can_user_see_validFrom], ["validUntilDateTime" | not can_user_see_validUntil])
        	, ["visibility" | not can_user_see_visibility])
}

fields = fields {
	is_user_visitor
	fields := array.concat(
    	array.concat(
    		["validFromDateTime" | not can_user_see_validFrom], ["validUntilDateTime" | not can_user_see_validUntil])
        	, ["visibility" | not can_user_see_visibility])
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

can_user_see_validFrom {
	token.payload.roles[_] == user_roles_for_validFrom[_]
}

can_user_see_validUntil  {
	token.payload.roles[_] == user_roles_for_validUntil[_]
}

can_user_see_visibility {
	token.payload.roles[_] == user_roles_for_visibility[_]
}

token = {"payload": payload} {
  [header, payload, signature] := io.jwt.decode(input.encodedJwt)
}