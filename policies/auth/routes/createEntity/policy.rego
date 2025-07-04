package policies.auth.routes.createEntity.policy

import data.policies.util.common.token as token
import data.policies.util.common.array as array
import data.policies.util.common.verification as verification
import data.policies.util.genericentities.roles as role_utils
import data.policies.fields.genericentities.policy as forbidden_fields

# By default, deny requests.
default allow = false

# Decide allow if any of the following section is true
# ----------------------------------------------
allow if {
	role_utils.is_user_admin("create")
	verification.is_email_verified
}

allow if {
	role_utils.is_user_editor("create")
	verification.is_email_verified
}

allow if {
	role_utils.is_user_member("create")
	verification.is_email_verified
}

allow if {
	role_utils.is_user_visitor("create")
	verification.is_email_verified
}

#-----------------------------------------------

# Decide allow if any of the following section is true
#-----------------------------------------------
allow if {
	role_utils.is_user_admin("create")
	verification.is_email_verified
	not is_owner_users_empty
	not is_owner_groups_empty
}

allow if {
	role_utils.is_user_editor("create")
	verification.is_email_verified
	not is_owner_users_empty
	not is_owner_groups_empty
}

allow if {
	role_utils.is_user_member("create")
	verification.is_email_verified
	not is_owner_users_empty
	not is_owner_groups_empty
}

allow if {
	role_utils.is_user_visitor("create")
	verification.is_email_verified
	not is_owner_users_empty
	not is_owner_groups_empty
}

#-----------------------------------------------

# Decide allow if any of the following section is true
#-----------------------------------------------
allow if {
	role_utils.is_user_admin("create")
	verification.is_email_verified
	not is_owner_users_empty
	not is_owner_groups_empty
	not is_viewer_users_empty
	not is_viewer_groups_empty
}

allow if {
	role_utils.is_user_editor("create")
	verification.is_email_verified
	not is_owner_users_empty
	not is_owner_groups_empty
	not is_viewer_users_empty
	not is_viewer_groups_empty
}

allow if {
	role_utils.is_user_member("create")
	verification.is_email_verified
	not is_owner_users_empty
	not is_owner_groups_empty
	not is_viewer_users_empty
	not is_viewer_groups_empty
}

allow if {
	role_utils.is_user_visitor("create")
	verification.is_email_verified
	not is_owner_users_empty
	not is_owner_groups_empty
	not is_viewer_users_empty
	not is_viewer_groups_empty
}

#-----------------------------------------------

# Decide allow if any of the following section is true
#-----------------------------------------------
allow if {
	role_utils.is_user_admin("create")
	verification.is_email_verified
	not is_owner_users_empty
	not is_owner_groups_empty
	not is_viewer_users_empty
	not is_viewer_groups_empty
	not is_owner_users_contains_user
	not is_owner_groups_contains_user_groups
}

allow if {
	role_utils.is_user_editor("create")
	verification.is_email_verified
	not is_owner_users_empty
	not is_owner_groups_empty
	not is_viewer_users_empty
	not is_viewer_groups_empty
	not is_owner_users_contains_user
	not is_owner_groups_contains_user_groups
}

allow if {
	role_utils.is_user_member("create")
	verification.is_email_verified
	not is_owner_users_empty
	not is_owner_groups_empty
	not is_viewer_users_empty
	not is_viewer_groups_empty
	not is_owner_users_contains_user
	not is_owner_groups_contains_user_groups
}

allow if {
	role_utils.is_user_visitor("create")
	verification.is_email_verified
	not is_owner_users_empty
	not is_owner_groups_empty
	not is_viewer_users_empty
	not is_viewer_groups_empty
	not is_owner_users_contains_user
	not is_owner_groups_contains_user_groups
}

#-----------------------------------------------

# Decide allow if any of the following section is true
#-----------------------------------------------
allow if {
	role_utils.is_user_admin("create")
	verification.is_email_verified
	not is_owner_users_empty
	not is_owner_groups_empty
	not is_viewer_users_empty
	not is_viewer_groups_empty
	not is_owner_users_contains_user
	not is_owner_groups_contains_user_groups
	not is_viewer_users_contains_user
	not is_viewer_groups_contains_user_groups
}

allow if {
	role_utils.is_user_editor("create")
	verification.is_email_verified
	not is_owner_users_empty
	not is_owner_groups_empty
	not is_viewer_users_empty
	not is_viewer_groups_empty
	not is_owner_users_contains_user
	not is_owner_groups_contains_user_groups
	not is_viewer_users_contains_user
	not is_viewer_groups_contains_user_groups
}

allow if {
	role_utils.is_user_member("create")
	verification.is_email_verified
	not is_owner_users_empty
	not is_owner_groups_empty
	not is_viewer_users_empty
	not is_viewer_groups_empty
	not is_owner_users_contains_user
	not is_owner_groups_contains_user_groups
	not is_viewer_users_contains_user
	not is_viewer_groups_contains_user_groups
}

allow if {
	role_utils.is_user_visitor("create")
	verification.is_email_verified
	not is_owner_users_empty
	not is_owner_groups_empty
	not is_viewer_users_empty
	not is_viewer_groups_empty
	not is_owner_users_contains_user
	not is_owner_groups_contains_user_groups
	not is_viewer_users_contains_user
	not is_viewer_groups_contains_user_groups
}

#-----------------------------------------------

# Helper functions
#-----------------------------------------------
is_owner_users_empty if {
	count(input.originalRecord.ownerUsers) == 0
}

is_owner_groups_empty if {
	count(input.originalRecord.ownerGroups) == 0
}

is_viewer_users_empty if {
	count(input.originalRecord.viewerUsers) == 0
}

is_viewer_groups_empty if {
	count(input.originalRecord.viewerGroups) == 0
}

is_owner_users_contains_user if {
	some user
	user = token.payload.sub
	some i
	input.originalRecord.ownerUsers[i] == user
}

is_owner_groups_contains_user_groups if {
	some group
	some i
	group = token.payload.groups[i]
	some j
	input.originalRecord.ownerGroups[j] == group
}

is_viewer_users_contains_user if {
	some user
	user = token.payload.sub
	some i
	input.originalRecord.viewerUsers[i] == user
}

is_viewer_groups_contains_user_groups if {
	some group
	some i
	group = token.payload.groups[i]
	some j
	input.originalRecord.viewerGroups[j] == group
}

payload_contains_any_field(fields) if {
	some field
	field = fields[_]
	input.requestPayload[field]
}

member_has_problem_with_groups if {
	input.requestPayload["ownerGroups"]
	some group
	group = input.requestPayload["ownerGroups"][_]
	not group_in_token_groups(group)
}

group_in_token_groups(group) if {
	some i
	token.payload.groups[i] == group
}

member_has_problem_with_groups if {
	input.requestPayload["ownerGroups"]
	not token.payload.groups[0]
}

allow if {
	input.httpMethod == "POST"
	input.requestPath == "/generic-entities"
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
	some i
	input.requestPayload.ownerUsers[i] == input.encodedJwt.payload.sub
	some j, k
	input.requestPayload.ownerGroups[j] == input.encodedJwt.payload.groups[k]
}