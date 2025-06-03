package policies.util.common.token

payload = payload if {
	[header, payload, signature] := io.jwt.decode(input.encodedJwt)
}
