package policies.util.common.verification

import data.policies.util.common.token as token

is_email_verified if {
	token.payload.email_verified == true
}
