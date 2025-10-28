package policies.auth.routes.entitiesThroughList.findEntitiesByListId.policy

import data.policies.util.common.verification as verification
import data.policies.util.entities.roles as entity_roles
import data.policies.util.lists.roles as list_roles
import data.policies.util.common.originalRecord as original_record

# Default deny
default allow = false

# Allow only when caller can find entities AND can see the target list
allow if {
    entity_find_allowed
    list_allowed
}

# Entity-find rules (mirror policies/auth/routes/entities/findEntities/policy.rego)
entity_find_allowed if {
    entity_roles.is_user_admin("find")
    verification.is_email_verified
}

entity_find_allowed if {
    entity_roles.is_user_editor("find")
    verification.is_email_verified
}

entity_find_allowed if {
    entity_roles.is_user_member("find")
    verification.is_email_verified
}

entity_find_allowed if {
    entity_roles.is_user_visitor("find")
    verification.is_email_verified
}

# List visibility rules (mirror policies/auth/routes/lists/findListById/policy.rego)

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

