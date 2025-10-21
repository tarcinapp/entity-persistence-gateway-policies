package policies.util.common.originalRecord

import data.policies.util.common.token as token

is_active if {
    input.originalRecord._validFromDateTime != null
    time.parse_rfc3339_ns(input.originalRecord._validFromDateTime) < time.now_ns()
    not is_passive
}

is_passive if {
    input.originalRecord._validUntilDateTime != null
    time.parse_rfc3339_ns(input.originalRecord._validUntilDateTime) <= time.now_ns()
}

is_pending if {
    input.originalRecord._validFromDateTime == null
}

is_public if {
    input.originalRecord._visibility == "public"
}

is_protected if {
    input.originalRecord._visibility == "protected"
}

is_private if {
    input.originalRecord._visibility == "private"
}

is_belong_to_user if {
    some i
    token.payload.sub = input.originalRecord._ownerUsers[i]
}

# Only consider group ownership if the user is not a direct owner
is_belong_to_users_groups if {
    not is_belong_to_user  # Check that user doesn't own through ownerUsers first
    some i
    token.payload.groups[i] in input.originalRecord._ownerGroups
}

is_user_in_viewerUsers if {
    some i
    token.payload.sub = input.originalRecord._viewerUsers[i]
}

is_user_in_viewerGroups if {
    some i
    token.payload.groups[i] in input.originalRecord._viewerGroups
}

has_value(fieldName) if {
    input.originalRecord[fieldName]
    input.originalRecord[fieldName] != null
}

is_empty(fieldName) if {
    not has_value(fieldName)
}