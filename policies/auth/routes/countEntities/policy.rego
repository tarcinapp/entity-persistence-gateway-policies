package policies.auth.routes.countEntities.policy


# Define roles
#-----------------------------------------------
administrative_roles := [
    "tarcinapp.admin",
    "tarcinapp.records.manage.admin",
    "tarcinapp.entities.manage.admin",
    "tarcinapp.records.count.admin",
    "tarcinapp.entities.count.admin"
]

editorial_roles := [
    "tarcinapp.editor",
    "tarcinapp.records.manage.editor",
    "tarcinapp.entities.manage.editor",
    "tarcinapp.records.count.editor",
    "tarcinapp.entities.count.editor"
]

member_roles := [
    "tarcinapp.member",
    "tarcinapp.records.manage.member",
    "tarcinapp.records.count.member",
    "tarcinapp.entities.manage.member",
    "tarcinapp.entities.count.member"
]

visitor_roles := [
    "tarcinapp.visitor",
    "tarcinapp.records.count.visitor",
    "tarcinapp.entities.count.visitor"
]
#-----------------------------------------------


# By default, deny requests.
default allow = false
#-----------------------------------------------


# Decide allow if any of the following section is true
#-----------------------------------------------
allow {
	is_user_admin
}

allow {
	is_user_editor
}

allow {
	is_user_member
   	not user_has_problem_with_mail_verification
}

allow {
	is_user_visitor
   	not user_has_problem_with_mail_verification
}
#-----------------------------------------------


# Determine user's role
#-----------------------------------------------
is_user_member {
	token.payload.roles[_] == member_roles[_]
}

is_user_editor {
    token.payload.roles[_] == editorial_roles[_]
}

is_user_admin {
    token.payload.roles[_] == administrative_roles[_]
}

is_user_visitor {
    token.payload.roles[_] == visitor_roles[_]
}
#-----------------------------------------------

user_has_problem_with_mail_verification {
	token.payload.email_verified != true
}

token = {"payload": payload} {
  [header, payload, signature] := io.jwt.decode(input.encodedJwt)
}