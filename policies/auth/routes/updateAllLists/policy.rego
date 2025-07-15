package policies.auth.routes.updateAllLists.policy

import data.policies.util.common.token as token
import data.policies.util.common.verification as verification
import data.policies.util.lists.roles as role_utils
import data.policies.util.common.array as array

# By default, deny requests.
default allow = false

#-----------------------------------------------

# Decide allow if any of the following section is true
#-----------------------------------------------
allow if {
    role_utils.is_user_admin("update")
    verification.is_email_verified
}

allow if {
    role_utils.is_user_editor("update")
    verification.is_email_verified
}

#-----------------------------------------------

token = {"payload": payload} if {
    [header, payload, signature] := io.jwt.decode(input.encodedJwt)
}