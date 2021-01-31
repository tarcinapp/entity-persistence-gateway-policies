package policies.auth.routes.replaceEntityById.policy

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

# members cannot update kind field by default
user_roles_for_kind := [
	"tarcinapp.records.fields.kind.manage",
	"tarcinapp.entities.fields.kind.manage",
  	"tarcinapp.records.fields.kind.update",
	"tarcinapp.entities.fields.kind.update"
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
# - user's validFrom value is in between now and 300 seconds before 
# and
# - member have any of the following roles
#
# That is, these roles give member to approve his own record
user_roles_for_validFrom := [
	"tarcinapp.records.fields.validFrom.manage",
	"tarcinapp.entities.fields.validFrom.manage",
    "tarcinapp.records.fields.validFrom.update",
	"tarcinapp.entities.fields.validFrom.update"
]

user_roles_to_see_validFrom := [
	"tarcinapp.records.fields.validFrom.find",
	"tarcinapp.entities.fields.validFrom.find"
]

# if record is being approved by a member, validFromDateTime cannot be before than the amount of seconds given below from now
# this option enforces members to approve records immediately
member_validFrom_range_in_seconds:= 300

# members can update validUntil value if
# - original record is active or pending
# and
# - user's validUntil value is in between now and 300 seconds before
# and
# - member have any of the following roles
#
# That is, these roles give member to inactivate his own record
user_roles_for_inactivating_record:= [
	"tarcinapp.records.fields.validUntil.manage",
	"tarcinapp.entities.fields.validUntil.manage",
  	"tarcinapp.records.fields.validUntil.update",
	"tarcinapp.entities.fields.validUntil.update"
]

user_roles_to_see_validUntil := [
	"tarcinapp.records.fields.validUntil.find",
	"tarcinapp.entities.fields.validUntil.find"
]

member_validUntil_range_for_inactivation_in_seconds := 300

# NOTE: FOLLOWING ROLES ARE NOT USED FOR NOW! THERE IS A TASK ABOUT IMPLEMENTING THESE ROLES
# LETTING USERS TO SEE THEIR INACTIVATED RECORDS ALSE REQUIRES THEM TO SEE THEIR INACTIVE RECORDS.
# NOT SURE, HOW TO BUILD THE APPLICATION LOGIC.
# --------------------------------------------------------------------------
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
user_roles_for_undoing_inactivating_record:= [
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
	not user_has_problem_with_creationDateTime
	not user_has_problem_with_lastUpdatedDateTime
	not user_has_problem_with_lastUpdatedBy
	not user_has_problem_with_createdBy
}

allow {
	is_user_member
	is_record_belongs_to_this_user 						# over user's groups or user's id
    not is_original_record_inactive 					# only pending and active records are updateable
    
	not member_has_problem_with_mail_verification		# email must be verified
	not user_has_problem_with_creationDateTime			# member cannot send any value for creationDateTime
	not user_has_problem_with_lastUpdatedDateTime		# member cannot send any value for lastUpdatedDateTime
	not user_has_problem_with_lastUpdatedBy				# member cannot send any value for lastUpdatedDateTime
	not user_has_problem_with_createdBy					# member cannot change the value for createdBy
	not member_has_problem_with_kind					# updating kind, requires some specific roles
	not member_has_problem_with_visibility				# updating visibilitiy, requires some specific roles
	not member_has_problem_with_ownerUsers				# member cannot remove himself from ownerUsers
	not member_has_problem_with_ownerGroups				# member cannot use any group name that he is not belongs to
    
	not member_has_problem_with_validFrom				# updating validFrom (approving) requires some specific roles, validFrom > (now - 60s)
	not member_has_problem_with_validUntil				# updating validUntil (deleting) requires some specific roles, (validUntil > now - 60s)
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
user_has_problem_with_creationDateTime {
	input.requestPayload["creationDateTime"]
}

user_has_problem_with_creationDateTime {
	input.requestPayload["creationDateTime"] == false
}

user_has_problem_with_lastUpdatedDateTime {
	input.requestPayload["lastUpdatedDateTime"]
}

user_has_problem_with_lastUpdatedDateTime {
	input.requestPayload["lastUpdatedDateTime"] == false
}

user_has_problem_with_createdBy {
	input.requestPayload["createdBy"]
}

user_has_problem_with_createdBy {
	input.requestPayload["createdBy"] == false
}

user_has_problem_with_lastUpdatedBy{
	input.requestPayload["lastUpdatedBy"]
}

user_has_problem_with_lastUpdatedBy{
	input.requestPayload["lastUpdatedBy"] == false
}

member_has_problem_with_mail_verification {
	token.payload.email_verified != true
}

member_has_problem_with_kind {
	input.requestPayload["kind"] != input.originalRecord["kind"]
	not can_member_update_kind
}

member_has_problem_with_visibility {
	input.requestPayload["visibility"]
	input.requestPayload["visibility"] != input.originalRecord["visibility"]
	not can_member_update_visibility
}

member_has_problem_with_ownerUsers {
	not user_id_in_ownerUsers
}

member_has_problem_with_ownerGroups {
  input.requestPayload["ownerGroups"]
  no_ownerGroups_item_in_users_groups
}

# default behavior.
# user not able to see the validFrom
# user sent a value for validFrom
member_has_problem_with_validFrom {
	not can_user_see_the_validFrom		# user cannot see the validFrom
	not can_member_update_validFrom 	# user cannot update validFrom
	payload_contains_validFrom			# but validFrom is given in payload
}

# user can see but cannot update
# original record have validFrom
# user should send a value
member_has_problem_with_validFrom {
	can_user_see_the_validFrom 			# user can see the validFrom
	not can_member_update_validFrom 	# he is not able to change value
	originalRecord_contains_validFrom	# validFrom is not null in original record
	not payload_contains_validFrom		# but user did not send any value for validFrom
}

# user can see but cannot update
# user's value is different than the original
member_has_problem_with_validFrom {
	can_user_see_the_validFrom 				# user can see the validFrom
	not can_member_update_validFrom 		# he is not able to change value
	not is_validFrom_equals_to_the_original # but the value he sent is not equals to the original
}

# user can update validFrom
# user tries to change validFrom
# but original value is not null
member_has_problem_with_validFrom {
	can_member_update_validFrom
	originalRecord_contains_validFrom
}

# user can update validFrom
# original value is null
# user tries to add a validFrom
# but validFrom is not in correct range
member_has_problem_with_validFrom {
	can_member_update_validFrom
	not originalRecord_contains_validFrom
	payload_contains_validFrom
	not is_validFrom_in_correct_range
}

member_has_problem_with_validUntil {
	not can_user_see_the_validUntil
	not can_user_inactivate_record
	payload_contains_validUntil
}

member_has_problem_with_validUntil {
	can_user_see_the_validUntil 		
	not can_user_inactivate_record 
	originalRecord_contains_validUntil
	not payload_contains_validUntil
}

member_has_problem_with_validUntil {
	can_user_see_the_validUntil 			
	not can_user_inactivate_record 	
	not is_validUntil_equals_to_the_original
}

# validUntil must be in correct range for inactivation
member_has_problem_with_validUntil {
	can_user_inactivate_record
	payload_contains_validUntil
    not is_validUntil_in_correct_range_for_inactivation
} 


# Following section contains utilities to check if a specific field exists in payload
#-----------------------------------------------
payload_contains_validFrom {
	input.requestPayload["validFromDateTime"]
}

payload_contains_validFrom {
	input.requestPayload["validFromDateTime"] == false
}

originalRecord_contains_validFrom {
	input.originalRecord["validFromDateTime"]
}

originalRecord_contains_validFrom {
	input.originalRecord["validFromDateTime"] == false
}

payload_contains_validUntil {
	input.requestPayload["validUntilDateTime"]
}

payload_contains_validUntil {
	input.requestPayload["validUntilDateTime"] == false
}

originalRecord_contains_validUntil {
	input.originalRecord["validUntilDateTime"]
}

originalRecord_contains_validUntil {
	input.originalRecord["validUntilDateTime"] == false
}

user_id_in_ownerUsers {
  input.requestPayload.ownerUsers[_] = token.payload.sub
}

#-----------------------------------------------

can_user_see_the_validFrom {
	token.payload.roles[_] = user_roles_to_see_validFrom[_]
}

can_user_see_the_validUntil {
	token.payload.roles[_] = user_roles_to_see_validUntil[_]
}

can_member_update_kind {
	user_roles_for_kind[_] = token.payload.roles[_]
}

can_member_update_visibility {
	user_roles_for_visibility[_] = token.payload.roles[_]
}

can_member_update_validFrom {
	user_roles_for_validFrom[_] = token.payload.roles[_]
}

can_user_inactivate_record {
	user_roles_for_inactivating_record[_] = token.payload.roles[_]
}


no_ownerGroups_item_in_users_groups {
	token.payload.groups[_] != input.requestPayload.ownerGroups[_]
}

is_record_belongs_to_this_user {
  input.originalRecord.ownerUsers[_] = token.payload.sub
}

is_validFrom_equals_to_the_original {
	input.requestPayload["validFromDateTime"] == input.originalRecord["validFromDateTime"]
}

is_validFrom_equals_to_the_original {
	not originalRecord_contains_validFrom
	not payload_contains_validFrom
}

is_validUntil_equals_to_the_original {
	input.requestPayload["validUntilDateTime"] == input.originalRecord["validUntilDateTime"]
}

is_validUntil_equals_to_the_original {
	not originalRecord_contains_validUntil
	not payload_contains_validUntil
}


is_record_belongs_to_this_user {
  input.originalRecord.ownerGroups[_] = token.payload.groups[_]
  input.originalRecord.visibility != "private"
}


is_validFrom_in_correct_range {
	nowSec := time.now_ns()/(1000*1000*1000)
	validFromSec := time.parse_rfc3339_ns(input.requestPayload.validFromDateTime)/(1000*1000*1000)
    
	validFromSec <= nowSec
    validFromSec > (nowSec - member_validFrom_range_in_seconds)

	validFromDifferenceInSeconds := nowSec-validFromSec
}

is_validUntil_in_correct_range_for_inactivation {
	nowSec := time.now_ns()/(1000*1000*1000)
    validUntilSec := time.parse_rfc3339_ns(input.requestPayload.validUntilDateTime)/(1000*1000*1000)

    validUntilSec <= nowSec
    validUntilSec > (nowSec - member_validUntil_range_for_inactivation_in_seconds)
}

is_original_record_active {
    is_record_validFrom_passed
    not is_record_validUntil_passed
}

is_original_record_pending {
	input.originalRecord.validFromDateTime = null
}

is_original_record_inactive {
	is_record_validUntil_passed
}

is_record_validFrom_passed {
	input.originalRecord.validFromDateTime != null
    time.parse_rfc3339_ns(input.originalRecord.validFromDateTime) < time.now_ns()
}

is_record_validUntil_passed {
	time.parse_rfc3339_ns(input.originalRecord.validUntilDateTime) <= time.now_ns()
}

token = {"payload": payload} {
  [header, payload, signature] := io.jwt.decode(input.encodedJwt)
}