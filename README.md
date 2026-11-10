# spring-kotlin-jwt-checks

Runnable checks for a Kotlin + Spring Boot 4 API protected by JWT bearer tokens.

I wrote this after reading JetBrains' [Secure Your APIs: OAuth2 and JWT for Beginners](https://blog.jetbrains.com/kotlin/2026/07/secure-your-apis-oauth2-and-jwt-for-beginners/) by Mdu Sibisi. The article explains the concepts well. I wanted tests that prove each protection actually holds, so I could see a check fail when I removed it.

Every test signs a real token and sends it through the real decoder. Spring's `jwt()` test helper skips the decoder, so it can't tell you whether your issuer, audience or algorithm checks work.

## Run it

Needs JDK 17+.

```bash
git clone https://github.com/kelvindesman/spring-kotlin-jwt-checks
cd spring-kotlin-jwt-checks
./gradlew test
```

No authorization server, no Docker, no cloud account. The test keys live in the repo.

## What gets checked

| Test | Expect | Why it matters |
|---|---|---|
| valid token with `read:documents` | 200 | baseline |
| no token | 401 | |
| valid token, wrong scope | 403 | authenticated is not the same as allowed |
| read scope tries to upload | 403 | scopes are per action |
| expired token | 401 | `exp` is enforced (60 s clock skew) |
| token from another issuer | 401 | `iss` check, [RFC 8725 §3.8](https://www.rfc-editor.org/rfc/rfc8725#section-3.8) |
| token minted for another API | 401 | `aud` check, [RFC 8725 §3.9](https://www.rfc-editor.org/rfc/rfc8725#section-3.9) |
| `alg: none`, no signature | 401 | [RFC 8725 §2.1](https://www.rfc-editor.org/rfc/rfc8725#section-2.1) |
| HS256 signed with the public key | 401 | algorithm confusion, [RFC 8725 §3.1](https://www.rfc-editor.org/rfc/rfc8725#section-3.1) |
| payload edited, signature kept | 401 | signature covers the claims |
| signed with the previous key | 200 | rotation without downtime |
| signed with a retired key | 401 | old keys really stop working |
| admin role + `documents:read:all` | 200 | `@PreAuthorize` with roles and permissions |
| admin role, no permission | 403 | both conditions required |
| permission, no admin role | 403 | |

## Try it by hand

```bash
./gradlew bootRun
```

In another terminal:

```bash
TOKEN=$(./scripts/mint-token.sh)
curl -i localhost:8080/api/documents -H "Authorization: Bearer $TOKEN"        # 200

curl -i localhost:8080/api/documents                                          # 401

curl -i localhost:8080/api/documents \
  -H "Authorization: Bearer $(AUD=billing-api ./scripts/mint-token.sh)"       # 401, wrong audience

curl -i localhost:8080/api/documents \
  -H "Authorization: Bearer $(KID=retired ./scripts/mint-token.sh)"           # 401, retired key

curl -i localhost:8080/api/admin/documents \
  -H "Authorization: Bearer $(ROLES='"admin"' PERMISSIONS='"documents:read:all"' ./scripts/mint-token.sh)"  # 200
```

`mint-token.sh` only needs `openssl`.

## How it differs from the article's code

- **No issuer lookup at startup.** The article's final `JwtDecoder` uses `JwtDecoders.fromIssuerLocation("https://myapp.com/auth")`, which fetches the issuer's metadata when the app starts. That URL isn't a real issuer, so the app won't boot until you point it at one (the article suggests [mock-oauth2-server](https://github.com/navikt/mock-oauth2-server)). This repo loads a local key set instead, so it runs offline and still checks `iss` and `aud`.
- **RS256 is pinned.** The decoder only accepts RS256, so `none` and HS256 tokens never reach a key.
- **Two trusted keys.** `current` and `previous` are both accepted, which is how you rotate a signing key without logging everyone out.
- **No authorization server dependency.** A resource server only needs `spring-boot-starter-security-oauth2-resource-server`.

## Layout

```
src/main/kotlin/.../SecurityConfig.kt      filter chain, decoder, validators, claim mapping
src/main/kotlin/.../DocumentController.kt  three endpoints
src/main/resources/keys/*.pub.pem          trusted public keys (current, previous)
src/test/resources/keys/*.pem              test-only private keys, including a retired one
src/test/kotlin/.../JwtSecurityTests.kt    the checks above
scripts/mint-token.sh                      mint a token for curl
```

The private keys in `src/test/resources/keys` are for these tests only. Never use them for anything real.

## License

MIT
