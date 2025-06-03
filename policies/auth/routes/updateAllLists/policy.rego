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

allow if {
    input.httpMethod == "PUT"
    input.requestPath == "/lists"
    input.requestPayload != null
    input.requestPayload != {}
    input.requestPayload.name != null
    input.requestPayload.name != ""
    input.requestPayload.description != null
    input.requestPayload.description != ""
    input.requestPayload.visibility != null
    input.requestPayload.visibility != ""
    input.requestPayload.ownerUsers != null
    input.requestPayload.ownerUsers != []
    input.requestPayload.ownerGroups != null
    input.requestPayload.ownerGroups != []
    input.requestPayload.validFromDateTime != null
    input.requestPayload.validFromDateTime != ""
    input.requestPayload.validUntilDateTime != null
    input.requestPayload.validUntilDateTime != ""
    input.requestPayload.validFromDateTime < input.requestPayload.validUntilDateTime
    input.requestPayload.validFromDateTime != null
    input.requestPayload.validFromDateTime != ""
    input.requestPayload.validUntilDateTime == null
    input.requestPayload.validFromDateTime == null
    input.requestPayload.validUntilDateTime != null
    input.requestPayload.validUntilDateTime != ""
    input.requestPayload.validFromDateTime == null
    input.requestPayload.validUntilDateTime == null
    input.requestPayload.ownerUsers[_] = input.encodedJwt.payload.sub
    input.requestPayload.ownerGroups[_] = input.encodedJwt.payload.groups[_]
}