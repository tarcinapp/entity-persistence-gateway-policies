package policies.fields.genericentities.policy

import data.policies.util.common.test as test

# This test checks if we can receive desired list of fields for given roles.
# Roles are given from the most upper level like tarcinapp.{rolename}
test_which_fields_forbidden_for_finding_admin if {
	which_fields_forbidden_for_finding = []
}

test_which_fields_forbidden_for_finding_editor if {
	which_fields_forbidden_for_finding = []
}

test_which_fields_forbidden_for_finding_member if {
	which_fields_forbidden_for_finding = []
}

test_which_fields_forbidden_for_finding_visitor if {
	which_fields_forbidden_for_finding = []
}

test_which_fields_forbidden_for_create_admin if {
	which_fields_forbidden_for_create = []
}

test_which_fields_forbidden_for_create_editor if {
	which_fields_forbidden_for_create = []
}

test_which_fields_forbidden_for_create_member if {
	which_fields_forbidden_for_create = []
}

test_which_fields_forbidden_for_create_visitor if {
	which_fields_forbidden_for_create = []
}

test_which_fields_forbidden_for_update_admin if {
	which_fields_forbidden_for_update = []
}

test_which_fields_forbidden_for_update_editor if {
	which_fields_forbidden_for_update = []
}

test_which_fields_forbidden_for_update_member if {
	which_fields_forbidden_for_update = []
}

test_which_fields_forbidden_for_update_visitor if {
	which_fields_forbidden_for_update = []
}

test_get_fields_for if {
	get_fields_for("admin", "find") = []
}

test_get_effective_fields_for if {
	get_effective_fields_for("admin", "find") = []
}

test_can_user_find_field if {
	can_user_find_field("name")
}

test_can_user_create_field if {
	can_user_create_field("name")
}

test_can_user_update_field if {
	can_user_update_field("name")
}

test_admin_find if {
	which_fields_forbidden_for_finding = [] with input as produce_input_doc_by_role(["tarcinapp.admin"])
}

test_admin_create if {
	which_fields_forbidden_for_create = [] with input as produce_input_doc_by_role(["tarcinapp.admin"])
}

test_admin_update if {
	which_fields_forbidden_for_update = [] with input as produce_input_doc_by_role(["tarcinapp.admin"])
}

test_editor_find if {
	which_fields_forbidden_for_finding = [] with input as produce_input_doc_by_role(["tarcinapp.editor"])
}

test_editor_create if {
	which_fields_forbidden_for_create = ["creationDateTime", "lastUpdatedDateTime", "lastUpdatedBy", "createdBy"] with input as produce_input_doc_by_role(["tarcinapp.editor"])
}

test_editor_update if {
	which_fields_forbidden_for_update = ["creationDateTime", "lastUpdatedDateTime", "lastUpdatedBy", "createdBy"] with input as produce_input_doc_by_role(["tarcinapp.editor"])
}

test_member_find if {
	which_fields_forbidden_for_finding = ["visibility"] with input as produce_input_doc_by_role(["tarcinapp.member"])
}

test_member_create if {
	which_fields_forbidden_for_create = ["visibility", "creationDateTime", "lastUpdatedDateTime", "lastUpdatedBy", "createdBy", "validFromDateTime", "validUntilDateTime", "ownerUsers"] with input as produce_input_doc_by_role(["tarcinapp.member"])
}

test_member_update if {
	which_fields_forbidden_for_update = ["visibility", "kind", "creationDateTime", "lastUpdatedDateTime", "lastUpdatedBy", "createdBy", "validFromDateTime", "validUntilDateTime"] with input as produce_input_doc_by_role(["tarcinapp.member"])
}

test_visitor_find if {
	which_fields_forbidden_for_finding = ["validFromDateTime", "validUntilDateTime", "visibility", "lastUpdatedBy", "lastUpdatedDateTime"] with input as produce_input_doc_by_role(["tarcinapp.visitor"])
}

test_editor_creationDateTime_create if {
	which_fields_forbidden_for_create = ["lastUpdatedDateTime", "lastUpdatedBy", "createdBy"] with input as produce_input_doc_by_role(["tarcinapp.editor", "tarcinapp.records.fields.creationDateTime.manage"])
	which_fields_forbidden_for_create = ["lastUpdatedDateTime", "lastUpdatedBy", "createdBy"] with input as produce_input_doc_by_role(["tarcinapp.editor", "tarcinapp.records.fields.creationDateTime.create"])
	which_fields_forbidden_for_create = ["lastUpdatedDateTime", "lastUpdatedBy", "createdBy"] with input as produce_input_doc_by_role(["tarcinapp.editor", "tarcinapp.entities.fields.creationDateTime.manage"])
	which_fields_forbidden_for_create = ["lastUpdatedDateTime", "lastUpdatedBy", "createdBy"] with input as produce_input_doc_by_role(["tarcinapp.editor", "tarcinapp.entities.fields.creationDateTime.create"])
	which_fields_forbidden_for_create = ["creationDateTime", "lastUpdatedDateTime", "lastUpdatedBy", "createdBy"] with input as produce_input_doc_by_role(["tarcinapp.editor", "tarcinapp.entities.fields.creationDateTime.find"])
	which_fields_forbidden_for_create = ["creationDateTime", "lastUpdatedDateTime", "lastUpdatedBy", "createdBy"] with input as produce_input_doc_by_role(["tarcinapp.editor", "tarcinapp.entities.fields.visibility.create"])
}

produce_input_doc_by_role(roles) = test_body if {
	test_body = {
		"encodedJwt": test.produce_token({
			"sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
			"name": "John Doe",
			"admin": true,
			"iat": 1516239022,
			"email_verified": true,
			"groups": ["my-group"],
			"roles": roles,
		}),
		"appShortcode": "tarcinapp",
	}
}
