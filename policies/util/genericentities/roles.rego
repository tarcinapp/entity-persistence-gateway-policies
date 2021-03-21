package policies.util.genericentities.roles

import data.policies.util.common.token as token

is_user_admin(operationType) {
	role := token.payload.roles[_]
	pattern := sprintf(`tarcinapp(((\.)|(\.(records|entities))|(\.(records|entities)(\.%s)))?)\.admin`, [operationType])
	regex.match(pattern, role)
}

is_user_editor(operationType) {
	role := token.payload.roles[_]
	pattern := sprintf(`tarcinapp(((\.)|(\.(records|entities))|(\.(records|entities)(\.%s)))?)\.editor`, [operationType])
	regex.match(pattern, role)
}

is_user_member(operationType) {
	role := token.payload.roles[_]
	pattern := sprintf(`tarcinapp(((\.)|(\.(records|entities))|(\.(records|entities)(\.%s)))?)\.member`, [operationType])
	regex.match(pattern, role)
}

is_user_visitor(operationType) {
	role := token.payload.roles[_]
	pattern := sprintf(`tarcinapp(((\.)|(\.(records|entities))|(\.(records|entities)(\.%s)))?)\.visitor`, [operationType])
	regex.match(pattern, role)
}