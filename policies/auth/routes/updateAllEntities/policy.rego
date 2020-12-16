package policies.auth.routes.updateAllEntities.policy

# Define roles
#-----------------------------------------------
administrative_roles := [
	"tarcinapp_admin",
    "tarcinapp.admin",
    "tarcinapp.records.manage.admin",
    "tarcinapp.records.create.admin",
    "tarcinapp.entities.manage.admin",
    "tarcinapp.entities.create.admin"
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

reason = "You don't have enough permissions to perform this operation" {
	not allow
}

#-----------------------------------------------


# Determine user's role
#-----------------------------------------------
is_user_admin {
    token.payload.roles[_] == administrative_roles[_]
}

token = {"payload": payload} {
  [header, payload, signature] := io.jwt.decode(input.encodedJwt)
}