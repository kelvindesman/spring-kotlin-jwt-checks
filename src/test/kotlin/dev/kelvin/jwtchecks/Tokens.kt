package dev.kelvin.jwtchecks

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.PlainJWT
import com.nimbusds.jwt.SignedJWT
import java.security.KeyFactory
import java.security.interfaces.RSAPrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Instant
import java.util.Base64
import java.util.Date

/** Mints real signed tokens so the tests go through the actual decoder. */
object Tokens {
    const val ISSUER = "https://auth.example.test"
    const val AUDIENCE = "documents-api"

    fun claims(
        scope: String = "read:documents",
        issuer: String = ISSUER,
        audience: String = AUDIENCE,
        expiresAt: Instant = Instant.now().plusSeconds(300),
        roles: List<String> = emptyList(),
        permissions: List<String> = emptyList(),
    ): JWTClaimsSet = JWTClaimsSet.Builder()
        .subject("reader-1")
        .issuer(issuer)
        .audience(audience)
        .issueTime(Date.from(Instant.now().minusSeconds(10)))
        .expirationTime(Date.from(expiresAt))
        .claim("scope", scope)
        .claim("roles", roles)
        .claim("permissions", permissions)
        .build()

    fun rs256(claims: JWTClaimsSet = claims(), kid: String = "current"): String {
        val jwt = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.RS256).keyID(kid).type(JOSEObjectType.JWT).build(),
            claims,
        )
        jwt.sign(RSASSASigner(privateKey(kid)))
        return jwt.serialize()
    }

    /** alg=none: no signature at all. */
    fun unsigned(claims: JWTClaimsSet = claims()): String = PlainJWT(claims).serialize()

    /** Classic algorithm confusion: HS256 with the server's public key as the HMAC secret. */
    fun hs256WithPublicKey(claims: JWTClaimsSet = claims()): String {
        val publicKeyBytes = javaClass.getResource("/keys/current.pub.pem")!!.readBytes()
        val jwt = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.HS256).keyID("current").type(JOSEObjectType.JWT).build(),
            claims,
        )
        jwt.sign(MACSigner(publicKeyBytes))
        return jwt.serialize()
    }

    /** Swap the payload of a valid token and keep its original signature. */
    fun tampered(valid: String, newClaims: JWTClaimsSet): String {
        val (header, _, signature) = valid.split(".")
        val payload = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(JSONObjectUtils.toJSONString(newClaims.toJSONObject()).toByteArray())
        return "$header.$payload.$signature"
    }

    private fun privateKey(kid: String): RSAPrivateKey {
        val pem = javaClass.getResource("/keys/$kid.pem")!!.readText()
        val der = Base64.getDecoder().decode(pem.lines().filterNot { it.startsWith("-----") }.joinToString(""))
        return KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(der)) as RSAPrivateKey
    }
}
