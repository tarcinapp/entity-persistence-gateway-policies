package policies.auth.routes.updateEntityById.policy


# Define roles
#-----------------------------------------------
administrative_roles := [
    "tarcinapp.admin",
    "tarcinapp.records.manage.admin",
    "tarcinapp.records.update.admin",
    "tarcinapp.entities.manage.admin",
    "tarcinapp.entities.update.admin"
]

editorial_roles := [
    "tarcinapp.editor",
    "tarcinapp.records.manage.editor",
    "tarcinapp.records.update.editor",
    "tarcinapp.entities.manage.editor",
    "tarcinapp.entities.update.editor"
]

member_roles := [
    "tarcinapp.member",
    "tarcinapp.records.manage.member",
    "tarcinapp.records.update.member",
    "tarcinapp.entities.manage.member",
    "tarcinapp.entities.update.member"
]

# members cannot update visibility field by default
user_roles_for_visibility := [
	"tarcinapp.records.fields.visibility.manage",
	"tarcinapp.entities.fields.visibility.manage",
  	"tarcinapp.records.fields.visibility.update",
	"tarcinapp.entities.fields.visibility.update"
]

# members can update validFrom value if
# - original record does not have validFrom
# and
# - user's validFrom value is in between now and 10 seconds before
# and
# - member have any of the following roles
#
# That is, thesse roles give member to approve his own record
user_roles_for_validFrom := [
	"tarcinapp.records.fields.validFrom.manage",
	"tarcinapp.entities.fields.validFrom.manage",
    "tarcinapp.records.fields.validFrom.update",
	"tarcinapp.entities.fields.validFrom.update"
]

# members can update validUntil value if
# - original record is active
# and
# - user's validUntil value is in between now and 10 seconds before
# and
# - member have any of the following roles
#
# That is, these roles give member to effectively delete his own record
user_roles_for_passifying_record:= [
	"tarcinapp.records.fields.validUntil.manage",
	"tarcinapp.entities.fields.validUntil.manage",
  	"tarcinapp.records.fields.validUntil.update",
	"tarcinapp.entities.fields.validUntil.update"
]

# members can update validUntil value if
# - original record is passive
# and
# - original record's validUntil date is in last 5 minutes
# and
# - user's validUntil value is exactly equals to 'null'
# and
# - member have any of the following roles
#
# That is, these roles give member to effectively undo his deletion in 5 minutes
user_roles_for_undoing_passifying_record:= [
	"tarcinapp.records.fields.validUntil.manage",
	"tarcinapp.entities.fields.validUntil.manage"
]

# visitiors cannot update any record

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
	not payload_contains_creationDateTime
	not payload_contains_lastUpdatedDateTime
}

allow {
	is_user_member
	is_record_belongs_to_this_user # over user's groups or user's id
    
	not member_has_problem_with_mail_verification
	not payload_contains_creationDateTime
	not payload_contains_lastUpdatedDateTime
	not member_has_problem_with_visibility
	not member_has_problem_with_ownerUsers
	not member_has_problem_with_ownerGroups
	not member_has_problem_with_validFrom
	not member_has_problem_with_validUntil
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
#-----------------------------------------------


# Check if user has a problem
#-----------------------------------------------
# if request has visibility field, then he must have roles to be able to create it
member_has_problem_with_mail_verification {
	token.payload.email_verified != true
}

member_has_problem_with_visibility {
	paylod_contains_visibility
  not can_member_update_visibility
}

member_has_problem_with_ownerUsers {
	payload_contains_ownerUsers
	not user_id_in_ownerUsers
}

member_has_problem_with_ownerGroups {
  payload_contains_ownerGroups
  no_ownerGroups_item_in_users_groups
}

member_has_problem_with_validFrom {
  payload_contains_validFrom
}

# if original record already have validFrom, members cannot update this value
member_has_problem_with_validFrom {
  original_record_already_have_validFrom
}

member_has_problem_with_validUntil {
  payload_contains_validUntil
}

# Following section contains utilities to check if a specific field exists in payload
#-----------------------------------------------
payload_contains_creationDateTime {
  input.requestPayload["creationDateTime"]
}

payload_contains_creationDateTime {
  input.requestPayload["creationDateTime"] == false
}

payload_contains_lastUpdatedDateTime {
  input.requestPayload["lastUpdatedDateTime"]
}

payload_contains_lastUpdatedDateTime {
  input.requestPayload["lastUpdatedDateTime"] == false
}

paylod_contains_visibility {
	input.requestPayload["visibility"]
}

paylod_contains_visibility {
	input.requestPayload["visibility"] == false
}

payload_contains_ownerUsers {
	input.requestPayload["ownerUsers"]
}

payload_contains_ownerUsers {
	input.requestPayload["ownerUsers"] == false
}

payload_contains_ownerGroups {
	input.requestPayload["ownerGroups"]
}

payload_contains_ownerGroups {
	input.requestPayload["ownerGroups"] == false
}

payload_contains_validFrom {
	input.requestPayload["validFromDateTime"]
}

payload_contains_validFrom {
	input.requestPayload["validFromDateTime"] == false
}

payload_contains_validUntil {
	input.requestPayload["validUntilDateTime"]
}

payload_contains_validUntil {
	input.requestPayload["validUntilDateTime"] == false
}

user_id_in_ownerUsers {
  input.requestPayload.ownerUsers[_] = token.payload.sub
}

#-----------------------------------------------

original_record_already_have_validFrom {
  input.originalRecord.validFrom
}

can_member_update_visibility {
	user_roles_for_visibility[_] = token.payload.roles[_]
}

can_member_update_validFrom {
	user_roles_for_validFrom[_] = token.payload.roles[_]
}


no_ownerGroups_item_in_users_groups {
	token.payload.groups[_] != input.requestPayload.ownerGroups[_]
}

is_record_belongs_to_this_user {
  input.originalRecord.ownerUsers[_] = token.payload.sub
}

is_record_belongs_to_this_user {
  input.originalRecord.ownerGroups[_] = token.payload.groups[_]
  input.originalRecord.visibility != "private"
}

token = {"payload": payload} {
  [header, payload, signature] := io.jwt.decode(input.encodedJwt)
}