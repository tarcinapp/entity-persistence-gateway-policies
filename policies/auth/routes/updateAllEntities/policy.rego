package policies.auth.routes.updateAllEntities.policy

import data.policies.util.genericentities.roles as role_utils
import data.policies.util.common.verification as verification

# By default, deny requests.
default allow = false
#-----------------------------------------------

allow {
	role_utils.is_user_admin("updateall")
  verification.is_email_verified
}


token = {"payload": payload} {
  [header, payload, signature] := io.jwt.decode(input.encodedJwt)
}