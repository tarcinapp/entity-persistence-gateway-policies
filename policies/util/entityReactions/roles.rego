package policies.util.entityReactions.roles

import data.policies.util.common.token as token

is_user_admin(operationType) if {
    role := token.payload.roles[_]
    pattern := sprintf(`%s(((\.)|(\.(records|entityReactions))|(\.(records|entityReactions)(\.%s)))?)\.admin`, [input.appShortcode, operationType])
    regex.match(pattern, role)
}

is_user_editor(operationType) if {
    not is_user_admin(operationType)
    role := token.payload.roles[_]
    pattern := sprintf(`%s(((\.)|(\.(records|entityReactions))|(\.(records|entityReactions)(\.%s)))?)\.editor`, [input.appShortcode, operationType])
    regex.match(pattern, role)
}

is_user_member(operationType) if {
    not is_user_admin(operationType)
    not is_user_editor(operationType)

    role := token.payload.roles[_]
    pattern := sprintf(`%s(((\.)|(\.(records|entityReactions))|(\.(records|entityReactions)(\.%s)))?)\.member`, [input.appShortcode, operationType])
    regex.match(pattern, role)
}

is_user_visitor(operationType) if {
    not is_user_admin(operationType)
    not is_user_editor(operationType)
    not is_user_member(operationType)

    role := token.payload.roles[_]
    pattern := sprintf(`%s(((\.)|(\.(records|entityReactions))|(\.(records|entityReactions)(\.%s)))?)\.visitor`, [input.appShortcode, operationType])
    regex.match(pattern, role)
}
