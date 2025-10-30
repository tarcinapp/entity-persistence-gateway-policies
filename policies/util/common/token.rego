package policies.util.common.token

payload := payload if {
	input.encodedJwt
	[header, payload, signature] := io.jwt.decode(input.encodedJwt)
}
