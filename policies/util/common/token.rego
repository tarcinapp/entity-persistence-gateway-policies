package policies.util.common.token

payload = payload {
	[header, payload, signature] := io.jwt.decode(input.encodedJwt)
}
