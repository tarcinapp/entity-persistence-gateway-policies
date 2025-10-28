package policies.auth.routes.lists.createListChild.policy

import data.policies.util.common.token as token
import data.policies.util.common.array as array
import data.policies.util.common.verification as verification
import data.policies.util.lists.roles as role_utils
import data.policies.util.common.originalRecord as original_record
import data.policies.fields.lists.policy as forbidden_fields

# By default, deny requests.
default allow = false

#-----------------------------------------------

# Admin users can create list children - they can see any parent list
#-----------------------------------------------
allow if {
	role_utils.is_user_admin("create")
	verification.is_email_verified
	# payload cannot contain any invalid field
	not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_create)
}

#-----------------------------------------------

# Editor users can create list children - they can see any parent list
#-----------------------------------------------
allow if {
	role_utils.is_user_editor("create")
	verification.is_email_verified
	# payload cannot contain any invalid field
	not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_create)
}

#-----------------------------------------------

# Member users can create list children if they can see the parent list and meet creation requirements
#-----------------------------------------------
allow if {
	role_utils.is_user_member("create")
	verification.is_email_verified
	can_user_see_parent_record
	# payload cannot contain any invalid field
	not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_create)
	# if user sent _ownerGroups, then all elements listed in the _ownerGroups array
	# must exists in the 'groups' field in token
	not member_has_problem_with_groups
}

#-----------------------------------------------

# User can see parent record checks (same logic as findListById)
#-----------------------------------------------

# user can see parent record, because it's his record
can_user_see_parent_record if {
    original_record.is_belong_to_user
    not original_record.is_passive                # record is either pending or active
}

# user can see parent record, because record belongs to his groups and record is not private
can_user_see_parent_record if {
    original_record.is_belong_to_users_groups
    not original_record.is_passive                # record is either pending or active
    not original_record.is_private                # record is either public or protected
}

# user can see parent record, because it is public and active record
can_user_see_parent_record if {
    original_record.is_public
    original_record.is_active
}

# user can see parent record, because he is in viewerUsers, and record is active
can_user_see_parent_record if {
    original_record.is_user_in_viewerUsers
    original_record.is_active
}

# user can see parent record, because he is in viewerGroups, and record is active
can_user_see_parent_record if {
    original_record.is_user_in_viewerGroups
    not original_record.is_private                # record is either public or protected
    original_record.is_active
}

# Visitors are not allowed to create list children (no visitor allow rule)
# Note: Even if a visitor can see a public active parent list, they cannot create children

#-----------------------------------------------

# Creation validation helpers (same logic as createList)
#-----------------------------------------------

payload_contains_any_field(fields) if {
	some field
	field = fields[_]
	input.requestPayload[field]
}

member_has_problem_with_groups if {
	input.requestPayload["_ownerGroups"]
	some group
	group = input.requestPayload["_ownerGroups"][_]
	not group_in_token_groups(group)
}

group_in_token_groups(group) if {
	some i
	token.payload.groups[i] == group
}

member_has_problem_with_groups if {
	input.requestPayload["_ownerGroups"]
	not token.payload.groups[0]
}