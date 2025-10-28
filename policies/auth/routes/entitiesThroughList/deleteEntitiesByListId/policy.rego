package policies.auth.routes.entitiesThroughList.deleteEntitiesByListId.policy

import data.policies.util.common.verification as verification
import data.policies.util.entities.roles as role_utils

# Default deny
default allow = false

# Only global/list admins are allowed to delete entities by list id.
allow if {
    role_utils.is_user_admin("delete")
    verification.is_email_verified
}

