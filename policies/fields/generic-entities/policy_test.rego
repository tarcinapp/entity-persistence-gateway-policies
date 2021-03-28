package policies.fields.genericentities.policy

import data.policies.util.common.test as test


# This test checks if we can receive desired list of fields for given roles.
# Roles are given from the most upper level like tarcinapp.{rolename}
test_admin_find {
	which_fields_forbidden_for_finding = []
        with input as produce_input_doc_by_role(["tarcinapp.admin"])
}

test_admin_create {
	which_fields_forbidden_for_create = []
        with input as produce_input_doc_by_role(["tarcinapp.admin"])
}

test_admin_find {
	which_fields_forbidden_for_update = []
        with input as produce_input_doc_by_role(["tarcinapp.admin"])
}

test_editor_find {
    which_fields_forbidden_for_finding = []
        with input as produce_input_doc_by_role(["tarcinapp.editor"])
}

test_editor_create {
	which_fields_forbidden_for_create = ["creationDateTime", "lastUpdatedDateTime", "lastUpdatedBy", "createdBy", "ownerUsers"]
        with input as produce_input_doc_by_role(["tarcinapp.editor"])
}

test_editor_update {
    which_fields_forbidden_for_update = ["creationDateTime", "lastUpdatedDateTime", "lastUpdatedBy", "createdBy", "ownerUsers"]
        with input as produce_input_doc_by_role(["tarcinapp.editor"])
}

test_member_find {
    which_fields_forbidden_for_finding = ["validFromDateTime", "validUntilDateTime", "visibility"]
        with input as produce_input_doc_by_role(["tarcinapp.member"])
}

test_member_create {
	which_fields_forbidden_for_create = ["validFromDateTime", "validUntilDateTime", "visibility", "creationDateTime", "lastUpdatedDateTime", "lastUpdatedBy", "createdBy", "ownerUsers"]
        with input as produce_input_doc_by_role(["tarcinapp.member"])
}

test_member_update {
    which_fields_forbidden_for_update = ["validFromDateTime", "validUntilDateTime", "visibility", "creationDateTime", "lastUpdatedDateTime", "lastUpdatedBy", "createdBy", "ownerUsers"]
        with input as produce_input_doc_by_role(["tarcinapp.member"])
}

test_visitor_find {
    which_fields_forbidden_for_finding = ["validFromDateTime", "validUntilDateTime", "visibility", "lastUpdatedBy", "lastUpdatedDateTime"]
        with input as produce_input_doc_by_role(["tarcinapp.visitor"])
}

test_editor_creationDateTime_create {
    which_fields_forbidden_for_create = ["lastUpdatedDateTime", "lastUpdatedBy", "createdBy", "ownerUsers"]
        with input as produce_input_doc_by_role(["tarcinapp.editor", "tarcinapp.records.fields.creationDateTime.manage"])

    which_fields_forbidden_for_create = ["lastUpdatedDateTime", "lastUpdatedBy", "createdBy", "ownerUsers"]
        with input as produce_input_doc_by_role(["tarcinapp.editor", "tarcinapp.records.fields.creationDateTime.create"])

    which_fields_forbidden_for_create = ["lastUpdatedDateTime", "lastUpdatedBy", "createdBy", "ownerUsers"]
        with input as produce_input_doc_by_role(["tarcinapp.editor", "tarcinapp.entities.fields.creationDateTime.manage"])

    which_fields_forbidden_for_create = ["lastUpdatedDateTime", "lastUpdatedBy", "createdBy", "ownerUsers"]
        with input as produce_input_doc_by_role(["tarcinapp.editor", "tarcinapp.entities.fields.creationDateTime.create"])

    which_fields_forbidden_for_create = ["creationDateTime", "lastUpdatedDateTime", "lastUpdatedBy", "createdBy", "ownerUsers"]
        with input as produce_input_doc_by_role(["tarcinapp.editor", "tarcinapp.entities.fields.creationDateTime.find"])

    which_fields_forbidden_for_create = ["creationDateTime", "lastUpdatedDateTime", "lastUpdatedBy", "createdBy", "ownerUsers"]
        with input as produce_input_doc_by_role(["tarcinapp.editor", "tarcinapp.entities.fields.visibility.create"])
}

produce_input_doc_by_role(roles) = test_body {
	test_body = {"encodedJwt": test.produce_token({
		"sub": "ebe92b0c-bda2-49d0-99d0-feb538aa7db6",
		"name": "John Doe",
		"admin": true,
		"iat": 1516239022,
		"email_verified": true,
		"groups": ["my-group"],
		"roles": roles,
	})}
}
