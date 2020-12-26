package policies.auth.routes.findEntityById.policy


# Define roles
#-----------------------------------------------
administrative_roles := [
    "tarcinapp.admin",
    "tarcinapp.records.manage.admin",
    "tarcinapp.entities.manage.admin",
    "tarcinapp.records.create.admin",
    "tarcinapp.entities.create.admin",
    "tarcinapp.records.find.admin",
    "tarcinapp.entities.find.admin"
]

editorial_roles := [
    "tarcinapp.editor",
    "tarcinapp.records.manage.editor",
    "tarcinapp.entities.manage.editor",
    "tarcinapp.records.create.editor",
    "tarcinapp.entities.create.editor",
    "tarcinapp.records.find.editor",
    "tarcinapp.entities.find.editor"
]

member_roles := [
    "tarcinapp.member",
    "tarcinapp.records.manage.member",
    "tarcinapp.records.find.member",
    "tarcinapp.entities.manage.member",
    "tarcinapp.entities.find.member"
]

visitor_roles := [
    "tarcinapp.visitor",
    "tarcinapp.records.find.visitor",
    "tarcinapp.entities.find.visitor"
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

allow {
	is_user_editor
}

allow {
	is_user_member
    can_user_see_this_record
   	not user_has_problem_with_mail_verification
}

allow {
	is_user_visitor
    is_original_record_public
    is_original_record_active
   	not user_has_problem_with_mail_verification
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

is_user_visitor {
    token.payload.roles[_] == visitor_roles[_]
}
#-----------------------------------------------

can_user_see_this_record {
    is_original_record_belongs_to_this_user
}

can_user_see_this_record {
    is_original_record_belongs_to_users_groups
}

can_user_see_this_record {
    is_original_record_public
    is_original_record_active
}

is_original_record_belongs_to_this_user {
    some i
    token.payload.sub = input.originalRecord.ownerUsers[i]
}

# if original record's ownerGroups array contains any of the groups of the user
# and the record is not private we can say that the record is visible to the user
is_original_record_belongs_to_users_groups {
    some i
    token.payload.groups[i] = input.originalRecord.ownerGroups[i]
    input.originalRecord.visibility != "private"
}

is_original_record_active {
    input.originalRecord.validFromDateTime != null
    time.parse_rfc3339_ns(input.originalRecord.validFromDateTime) < time.now_ns()
    not is_record_validUntil_passed
}

record_validUntil_is_not_passed {
    input.originalRecord.validUntilDateTime = null
}

is_record_validUntil_passed {
	time.parse_rfc3339_ns(input.originalRecord.validUntilDateTime) <= time.now_ns()
}

user_has_problem_with_mail_verification {
	token.payload.email_verified != true
}

is_original_record_public {
	input.originalRecord.visibility = "public"
}

token = {"payload": payload} {
  [header, payload, signature] := io.jwt.decode(input.encodedJwt)
}