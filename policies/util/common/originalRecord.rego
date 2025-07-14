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

is_belong_to_users_groups if {
    some i
    token.payload.groups[i] = input.originalRecord._ownerGroups[i]
}

is_user_in_viewerUsers if {
    some i
    token.payload.sub = input.originalRecord._viewerUsers[i]
}

is_user_in_viewerGroups if {
    some i
    token.payload.groups[i] = input.originalRecord._viewerGroups[i]
}

has_value(fieldName) if {
    input.originalRecord[fieldName]
    input.originalRecord[fieldName] != null
}

is_empty(fieldName) if {
    not has_value(fieldName)
}