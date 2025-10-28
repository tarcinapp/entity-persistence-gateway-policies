package policies.auth.routes.listsThroughEntity.findListsByEntityId.policy

import data.policies.util.common.token as token
import data.policies.util.common.verification as verification
import data.policies.util.lists.roles as lists_role_utils
import data.policies.util.entities.roles as entities_role_utils
import data.policies.util.common.originalRecord as original_record

# By default, deny requests.
default allow = false

# Allow only if caller can both: (1) query lists, and (2) see the entity (originalRecord)
allow if {
    can_find_lists
    can_see_entity
}

can_find_lists if {
    lists_role_utils.is_user_admin("find")
    verification.is_email_verified
}

can_find_lists if {
    lists_role_utils.is_user_editor("find")
    verification.is_email_verified
}

can_find_lists if {
    lists_role_utils.is_user_member("find")
    verification.is_email_verified
}

can_find_lists if {
    lists_role_utils.is_user_visitor("find")
    verification.is_email_verified
}

# entity visibility (same logic as findEntityById)
can_see_entity if {
    entities_role_utils.is_user_admin("find")
    verification.is_email_verified
}

can_see_entity if {
    entities_role_utils.is_user_editor("find")
    verification.is_email_verified
}

can_see_entity if {
    entities_role_utils.is_user_member("find")
    verification.is_email_verified
    can_user_see_this_record
}

can_see_entity if {
    entities_role_utils.is_user_visitor("find")
    verification.is_email_verified
    original_record.is_public
    original_record.is_active
}

# user can see this record, because it's his record
can_user_see_this_record if {
    original_record.is_belong_to_user
    not original_record.is_passive
}

# user can see this record, because record belongs to his groups and record is not private
can_user_see_this_record if {
    original_record.is_belong_to_users_groups
    not original_record.is_passive
    not original_record.is_private
}

# user can see this record, because it is public and active record
can_user_see_this_record if {
    original_record.is_public
    original_record.is_active
}

# user can see this record, because he is in viewerUsers, and record is active
can_user_see_this_record if {
    original_record.is_user_in_viewerUsers
    original_record.is_active
}

# user can see this record, because he is in viewerGroups, and record is active
can_user_see_this_record if {
    original_record.is_user_in_viewerGroups
    not original_record.is_private
    original_record.is_active
}

