package policies.auth.routes.entitiesThroughList.createEntityByListId.policy

import data.policies.util.common.token as token
import data.policies.util.common.array as array
import data.policies.util.common.verification as verification
import data.policies.util.entities.roles as entity_roles
import data.policies.util.lists.roles as list_roles
import data.policies.fields.entities.policy as forbidden_fields
import data.policies.util.common.originalRecord as original_record

# This policy allows creating an entity under a list when BOTH of the
# following are true:
#  1) the caller is allowed to create the entity (same rules as createEntity)
#  2) the caller is allowed to view the target list (same rules as findListById)
#
# Expectations on input shape:
#  - input.requestPayload contains the entity data (used by createEntity)
#  - input.originalRecord contains the list record to evaluate visibility (used by findListById)

# Default deny
default allow = false

# Final allow: must satisfy both creation rules and list visibility rules
allow if {
    create_allowed
    list_allowed
}

# Creation rules (aligned with createEntity)
create_allowed if {
    entity_roles.is_user_admin("create")
    verification.is_email_verified
    not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_create)
}

create_allowed if {
    entity_roles.is_user_editor("create")
    verification.is_email_verified
    not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_create)
}

create_allowed if {
    entity_roles.is_user_member("create")
    not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_create)
    verification.is_email_verified
    not member_has_problem_with_groups
}

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

# ------------------------------
# List visibility rules (aligned with findListById)
# ------------------------------
list_allowed if {
    list_roles.is_user_admin("find")
    verification.is_email_verified
}

list_allowed if {
    list_roles.is_user_editor("find")
    verification.is_email_verified
}

list_allowed if {
    list_roles.is_user_member("find")
    verification.is_email_verified
    can_user_see_this_record
}

list_allowed if {
    list_roles.is_user_visitor("find")
    verification.is_email_verified
    original_record.is_public
    original_record.is_active
}

can_user_see_this_record if {
    original_record.is_belong_to_user
    not original_record.is_passive
}

can_user_see_this_record if {
    original_record.is_belong_to_users_groups
    not original_record.is_passive
    not original_record.is_private
}

can_user_see_this_record if {
    original_record.is_public
    original_record.is_active
}

can_user_see_this_record if {
    original_record.is_user_in_viewerUsers
    original_record.is_active
}

can_user_see_this_record if {
    original_record.is_user_in_viewerGroups
    not original_record.is_private
    original_record.is_active
}


