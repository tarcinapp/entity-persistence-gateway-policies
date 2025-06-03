package policies.util.common.originalRecord

import data.policies.util.common.token as token

is_active if {
    input.originalRecord.validFromDateTime != null
    time.parse_rfc3339_ns(input.originalRecord.validFromDateTime) < time.now_ns()
    not is_passive
}

is_passive if {
    input.originalRecord.validUntilDateTime != null
    time.parse_rfc3339_ns(input.originalRecord.validUntilDateTime) <= time.now_ns()
}

is_pending if {
    input.originalRecord.validFromDateTime == null
}

is_public if {
    input.originalRecord.visibility == "public"
}

is_belong_to_user if {
    some i
    token.payload.sub = input.originalRecord.ownerUsers[i]
}

is_belong_to_users_groups if {
    some i
    token.payload.groups[i] = input.originalRecord.ownerGroups[i]
}

is_user_in_viewerUsers if {
    some i
    token.payload.sub = input.originalRecord.viewerUsers[i]
}

is_user_in_viewerGroups if {
    some i
    token.payload.groups[i] = input.originalRecord.viewerGroups[i]
}

has_value(fieldName) if {
    input.originalRecord[fieldName]
    input.originalRecord[fieldName] != null
}

is_empty(fieldName) if {
    not has_value(fieldName)
}