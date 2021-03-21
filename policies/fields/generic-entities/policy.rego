package policies.fields.genericentities.policy

# admins are allowed to see and manage all fields by definition
# if a user can manage a field, he can create, update and find
# if a user can create a field, he can find the field
# if a user can update a field, he can find the field
# if a user can find a field, does not mean that he cannot create, update and manage

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
# ---
# admin
which_fields_forbidden_for_finding = [] {
	is_user_admin("find")
}
which_fields_forbidden_for_create = [] {
    is_user_admin("create")
}
which_fields_forbidden_for_update = [] {
    is_user_admin("update")
}
which_fields_forbidden_for_manage = [] {
    is_user_admin("manage")
}

# editor
which_fields_forbidden_for_finding = which_fields_forbidden_for_finding {
	is_user_editor("find")

    # all fields into single array
    fields := forbiddenFieldsForEditorsToFind
    
    # admin users can see all fields, no need to concat with upper level forbidden fields

    # add field to the result fields array if user cannot see the field.
	which_fields_forbidden_for_finding := [field | not can_user_find_field(fields[i]); field := fields[i]]
}
which_fields_forbidden_for_create = which_fields_forbidden_for_create {
	is_user_editor("create")

    fields := array.concat(forbiddenFieldsForEditorsToFind, forbiddenFieldsForEditorsToCreate)

     # add field to the result fields array if user create see the field.
	which_fields_forbidden_for_create := [field | not can_user_create_field(fields[i]); field := fields[i]]
}
which_fields_forbidden_for_update = [] {
	is_user_editor("update")
}
which_fields_forbidden_for_manage = which_fields_forbidden_for_manage {
    is_user_editor("manage")

    # concat all fields into single array, forbidden fields for manage is calculated 
    # from the collection of all fields
    fields := array.concat(
        array.concat(forbiddenFieldsForEditorsToManage, forbiddenFieldsForEditorsToCreate), 
        array.concat(forbiddenFieldsForEditorsToUpdate, forbiddenFieldsForEditorsToFind)
    )

    which_fields_forbidden_for_manage := [field | not can_user_manage_field(fields[i]); field := fields[i]]
}

# member
which_fields_forbidden_for_finding = which_fields_forbidden_for_finding {
	is_user_member("find")

    # concat all fields into single array
    fields_member := array.concat(
        array.concat(forbiddenFieldsForMembersToManage, forbiddenFieldsForMembersToCreate), 
        array.concat(forbiddenFieldsForMembersToUpdate, forbiddenFieldsForMembersToFind)
    )

    # concat editor fields (upper level forbidden fields)
    fields_editor := array.concat(
        array.concat(forbiddenFieldsForEditorsToManage, forbiddenFieldsForEditorsToCreate), 
        array.concat(forbiddenFieldsForEditorsToUpdate, forbiddenFieldsForEditorsToFind)
    )

    # merge all forbidden fields into single array
    fields := array.concat(fields_member, fields_editor)

	# add field to the result fields array if user cannot see the field.
	which_fields_forbidden_for_finding := [field | not can_user_find_field(fields[i]); field := fields[i]]
}

which_fields_forbidden_for_finding = which_fields_forbidden_for_finding {
	is_user_visitor("find")

	# concat all fields into single array
    fields_visitor := array.concat(
        array.concat(forbiddenFieldsForVisitorsToManage, forbiddenFieldsForVisitorsToCreate), 
        array.concat(forbiddenFieldsForVisitorsToUpdate, forbiddenFieldsForVisitorsToFind)
    )

    # concat all fields into single array
    fields_member := array.concat(
        array.concat(forbiddenFieldsForMembersToManage, forbiddenFieldsForMembersToCreate), 
        array.concat(forbiddenFieldsForMembersToUpdate, forbiddenFieldsForMembersToFind)
    )

    # concat editor fields (upper level forbidden fields)
    fields_editor := array.concat(
        array.concat(forbiddenFieldsForEditorsToManage, forbiddenFieldsForEditorsToCreate), 
        array.concat(forbiddenFieldsForEditorsToUpdate, forbiddenFieldsForEditorsToFind)
    )

    fields := array.concat(
        array.concat(fields_visitor, fields_member),
        fields_editor
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
