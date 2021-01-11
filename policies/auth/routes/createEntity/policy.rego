package policies.auth.routes.createEntity.policy


# Define roles
#-----------------------------------------------
administrative_roles := [
    "tarcinapp.admin",
    "tarcinapp.records.manage.admin",
    "tarcinapp.records.create.admin",
    "tarcinapp.entities.manage.admin",
    "tarcinapp.entities.create.admin"
]

editorial_roles := [
    "tarcinapp.editor",
    "tarcinapp.records.manage.editor",
    "tarcinapp.records.create.editor",
    "tarcinapp.entities.manage.editor",
    "tarcinapp.entities.create.editor"
]

member_roles := [
    "tarcinapp.member",
    "tarcinapp.records.manage.member",
    "tarcinapp.records.create.member",
    "tarcinapp.entities.manage.member",
    "tarcinapp.entities.create.member"
]

user_roles_for_visibility := [
	"tarcinapp.records.fields.visibility.manage",
	"tarcinapp.entities.fields.visibility.manage",
    "tarcinapp.records.fields.visibility.create",
	"tarcinapp.entities.fields.visibility.create"
]

user_roles_for_validFrom := [
	"tarcinapp.records.fields.validFrom.manage",
	"tarcinapp.entities.fields.validFrom.manage",
    "tarcinapp.records.fields.validFrom.create",
	"tarcinapp.entities.fields.validFrom.create"
]

# creating an invalid record at the time of creation does not make sense for members
# user_roles_for_validUntil:= []

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
    not payload_contains_createdBy
    not payload_contains_lastUpdatedDateTime
    not payload_contains_lastUpdatedBy
}

allow {
	is_user_member
   	not member_has_problem_with_mail_verification
    not payload_contains_creationDateTime
    not member_has_problem_with_visibility
    not member_has_problem_with_ownerUsers
    not member_has_problem_with_ownerGroups
    not member_has_problem_with_validFrom
    not member_has_problem_with_validUntil
    not payload_contains_lastUpdatedDateTime
    not payload_contains_lastUpdatedBy
    not payload_contains_createdBy
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
    not can_member_create_visibility
}

member_has_problem_with_ownerUsers {
	payload_contains_ownerUsers
}

member_has_problem_with_ownerGroups {
	payload_contains_ownerGroups
    no_ownerGroups_item_in_users_groups
}

member_has_problem_with_validFrom {
	payload_contains_validFrom
    not can_member_create_validFrom
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

payload_contains_createdBy {
	input.requestPayload["createdBy"]
}

payload_contains_createdBy {
	input.requestPayload["createdBy"] == false
}

payload_contains_lastUpdatedBy {
	input.requestPayload["lastUpdatedBy"]
}

payload_contains_lastUpdatedBy {
	input.requestPayload["lastUpdatedBy"] == false
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
#-----------------------------------------------


can_member_create_visibility {
	user_roles_for_visibility[_] = token.payload.roles[_]
}

can_member_create_validFrom {
	user_roles_for_validFrom[_] = token.payload.roles[_]
}

no_ownerGroups_item_in_users_groups {
	token.payload.groups[_] != input.requestPayload.ownerGroups[_]
}

token = {"payload": payload} {
  [header, payload, signature] := io.jwt.decode(input.encodedJwt)
}