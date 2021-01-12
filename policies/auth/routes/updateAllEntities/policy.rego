package policies.auth.routes.updateAllEntities.policy

# Define roles
#-----------------------------------------------
administrative_roles := [
  "tarcinapp.admin",
  "tarcinapp.records.manage.admin",
  "tarcinapp.records.update.admin",
  "tarcinapp.entities.manage.admin",
  "tarcinapp.entities.update.admin"
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

#-----------------------------------------------


# Determine user's role
#-----------------------------------------------
is_user_admin {
    token.payload.roles[_] == administrative_roles[_]
}

token = {"payload": payload} {
  [header, payload, signature] := io.jwt.decode(input.encodedJwt)
}