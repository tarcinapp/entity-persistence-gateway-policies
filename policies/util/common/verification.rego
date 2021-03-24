package policies.util.common.verification


import data.policies.util.common.token as token

is_email_verified {
    token.payload.email_verified == true
}