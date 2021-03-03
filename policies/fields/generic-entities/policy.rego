package policies.fields.genericentities.policy

# admins are allowed to see and manage all fields by definition
# if an user can manage a field, he can create, update and find
# if an user can create a field, he can find the field
# if an user can update a field, he can find the field
# if an user can find a field, does not mean that he cannot create, update and manage

#!!!!!!!!!!!!!!! TODO concat forbiddenfields from upper levels

default forbiddenFieldsForEditorsToFind     = []
default forbiddenFieldsForEditorsToUpdate   = []
default forbiddenFieldsForEditorsToCreate   = []
default forbiddenFieldsForEditorsToManage   = ["creationDateTime", "lastUpdatedDateTime", "lastUpdatedBy", "createdBy"]

default forbiddenFieldsForMembersToFind     = ["validFromDateTime", "validUntilDateTime", "visibility"] 
default forbiddenFieldsForMembersToUpdate   = []
default forbiddenFieldsForMembersToCreate   = []
default forbiddenFieldsForMembersToManage   = []

default forbiddenFieldsForVisitorsToFind    = [] 
default forbiddenFieldsForVisitorsToUpdate  = []
default forbiddenFieldsForVisitorsToCreate  = []
default forbiddenFieldsForVisitorsToManage  = []

# Prepare forbidden fields for `find` operations
which_fields_forbidden_for_finding = [] {
	is_user_admin("find")
}

which_fields_forbidden_for_finding = which_fields_forbidden_for_finding {
	is_user_editor("find")

    # concat all fields into single array
    fields := array.concat(
        array.concat(forbiddenFieldsForEditorsToManage, forbiddenFieldsForEditorsToCreate), 
        array.concat(forbiddenFieldsForEditorsToUpdate, forbiddenFieldsForEditorsToFind)
    )

    # add field to the result fields array if user cannot see the field.
	which_fields_forbidden_for_finding := [field | not can_user_find_field(fields[i]); field := fields[i]]
}

which_fields_forbidden_for_finding = which_fields_forbidden_for_finding {
	is_user_member("find")

    # concat all fields into single array
    fields := array.concat(
        array.concat(forbiddenFieldsForMembersToManage, forbiddenFieldsForMembersToCreate), 
        array.concat(forbiddenFieldsForMembersToUpdate, forbiddenFieldsForMembersToFind)
    )

	# add field to the result fields array if user cannot see the field.
	which_fields_forbidden_for_finding := [field | not can_user_find_field(fields[i]); field := fields[i]]
}

which_fields_forbidden_for_finding = which_fields_forbidden_for_finding {
	is_user_visitor("find")

	# concat all fields into single array
    fields := array.concat(
        array.concat(forbiddenFieldsForVisitorsToManage, forbiddenFieldsForVisitorsToCreate), 
        array.concat(forbiddenFieldsForVisitorsToUpdate, forbiddenFieldsForVisitorsToFind)
    )

	# add field to the result fields array if user can see the field.
	which_fields_forbidden_for_finding := [field | not can_user_find_field(fields[i]); field := fields[i]]
}
#-----------------------------------------------

can_user_find_field(fieldName) {
	role = token.payload.roles[_]
    pattern := sprintf(`tarcinapp\.(records|entities)\.fields\.%s\.(find|update|manage)`, [fieldName])
   	regex.match(pattern, role)
}

can_user_create_field(fieldName) {
	role = token.payload.roles[_]
    pattern := sprintf(`tarcinapp\.(records|entities)\.fields\.%s\.(create|manage)`, [fieldName])
   	regex.match(pattern, role)
}

can_user_update_field(fieldName) {
	role = token.payload.roles[_]
    pattern := sprintf(`tarcinapp\.(records|entities)\.fields\.%s\.(update|manage)`, [fieldName])
   	regex.match(pattern, role)
}

can_user_manage_field(fieldName) {
	role = token.payload.roles[_]
    pattern := sprintf(`tarcinapp\.(records|entities)\.fields\.%s\.(manage)`, [fieldName])
   	regex.match(pattern, role)
}

is_user_admin(operationType) {
    role = token.payload.roles[_]
    pattern := sprintf(`tarcinapp(((\.)|(\.(records|entities))|(\.(records|entities)(\.%s)))?)\.admin`, [operationType])
    regex.match(pattern, role)
}

is_user_editor(operationType) {
    role = token.payload.roles[_]
    pattern := sprintf(`tarcinapp(((\.)|(\.(records|entities))|(\.(records|entities)(\.%s)))?)\.editor`, [operationType])
    regex.match(pattern, role)
}

is_user_member(operationType) {
    role = token.payload.roles[_]
    pattern := sprintf(`tarcinapp(((\.)|(\.(records|entities))|(\.(records|entities)(\.%s)))?)\.member`, [operationType])
    regex.match(pattern, role)
}

is_user_visitor(operationType) {
    role = token.payload.roles[_]
    pattern := sprintf(`tarcinapp(((\.)|(\.(records|entities))|(\.(records|entities)(\.%s)))?)\.visitor`, [operationType])
    regex.match(pattern, role)
}

token = {"payload": payload} {
  [header, payload, signature] := io.jwt.decode(input.encodedJwt)
}
