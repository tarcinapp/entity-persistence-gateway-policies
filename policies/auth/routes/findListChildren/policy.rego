package policies.auth.routes.findListChildren.policy

import data.policies.util.common.token as token
import data.policies.util.common.verification as verification
import data.policies.util.lists.roles as role_utils
import data.policies.util.common.originalRecord as original_record

# By default, deny requests.
default allow = false

#-----------------------------------------------

# Admin and editor users are always allowed to retrieve the list children
#-----------------------------------------------
allow if {
	role_utils.is_user_admin("find")
    verification.is_email_verified
}

allow if {
	role_utils.is_user_editor("find")
    verification.is_email_verified
}

#-----------------------------------------------

# Members can see list children if they can see the parent list
#-----------------------------------------------
allow if {
    role_utils.is_user_member("find")
    verification.is_email_verified
    can_user_see_this_record
}

#-----------------------------------------------

# Visitors are allowed to retrieve children only of active and public lists
#-----------------------------------------------
allow if {
    role_utils.is_user_visitor("find")
    verification.is_email_verified
    original_record.is_public
    original_record.is_active
}

#-----------------------------------------------

# user can see this record's children, because it's his record
can_user_see_this_record if {
    original_record.is_belong_to_user
    not original_record.is_passive                # record is either pending or active
}

# user can see this record's children, because record belongs to his groups and record is not private
can_user_see_this_record if {
    original_record.is_belong_to_users_groups
    not original_record.is_passive                # record is either pending or active
    not original_record.is_private                # record is either public or protected
}

# user can see this record's children, because it is public and active record
can_user_see_this_record if {
    original_record.is_public
    original_record.is_active
}

# user can see this record's children, because he is in viewerUsers, and record is active
can_user_see_this_record if {
    original_record.is_user_in_viewerUsers
    original_record.is_active
}

# user can see this record's children, because he is in viewerGroups, and record is active
can_user_see_this_record if {
    original_record.is_user_in_viewerGroups
    not original_record.is_private                # record is either public or protected
    original_record.is_active
}