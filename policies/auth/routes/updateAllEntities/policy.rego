package policies.auth.routes.updateAllEntities.policy

import data.policies.util.genericentities.roles as role_utils

# By default, deny requests.
default allow = false
#-----------------------------------------------

allow {
	role_utils.is_user_admin("updateall")
}


token = {"payload": payload} {
  [header, payload, signature] := io.jwt.decode(input.encodedJwt)
}