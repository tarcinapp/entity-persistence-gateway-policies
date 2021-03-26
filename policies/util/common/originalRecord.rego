package policies.util.common.originalRecord

import data.policies.util.common.token as token

is_active {
    input.originalRecord.validFromDateTime != null
    time.parse_rfc3339_ns(input.originalRecord.validFromDateTime) < time.now_ns()
    not is_passive
}

is_passive {
    input.originalRecord.validUntilDateTime != null
    time.parse_rfc3339_ns(input.originalRecord.validUntilDateTime) <= time.now_ns()
}

is_pending {
    input.originalRecord.validFromDateTime == null
}

is_public {
    input.originalRecord.visibility = "public"
}

is_belong_to_user {
    some i
    token.payload.sub = input.originalRecord.ownerUsers[i]
}

is_belong_to_users_groups {
    some i
    token.payload.groups[i] = input.originalRecord.ownerGroups[i]
}