package dev.kelvin.jwtchecks

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.io.ClassPathResource
import org.springframework.http.HttpMethod
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtValidators
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter
import org.springframework.security.web.SecurityFilterChain
import java.security.KeyFactory
import java.security.interfaces.RSAPublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
class SecurityConfig(
    @Value("\${app.jwt.issuer}") private val issuer: String,
    @Value("\${app.jwt.audience}") private val audience: String,
) {

    // Keys we accept, by kid. Rotating = add the new key, move signing to it,
    // and drop the old one once its tokens have expired.
    private val trustedKeys = listOf("current", "previous")

    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .csrf { it.disable() }
            .authorizeHttpRequests {
                it.requestMatchers(HttpMethod.GET, "/api/documents").hasAuthority("SCOPE_read:documents")
                it.requestMatchers(HttpMethod.POST, "/api/documents").hasAuthority("SCOPE_write:documents")
                it.anyRequest().authenticated()
            }
            .oauth2ResourceServer {
                it.jwt { jwt ->
                    jwt.decoder(jwtDecoder())
                    jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())
                }
            }
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
        return http.build()
    }

    @Bean
    fun jwtDecoder(): JwtDecoder {
        val jwks = JWKSet(trustedKeys.map { kid ->
            RSAKey.Builder(loadPublicKey("keys/$kid.pub.pem"))
                .keyID(kid)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .build()
        })

        // Pin RS256. Anything else (none, HS256 signed with the public key) never reaches a key.
        val processor = DefaultJWTProcessor<SecurityContext>()
        processor.setJWSKeySelector(JWSVerificationKeySelector(JWSAlgorithm.RS256, ImmutableJWKSet<SecurityContext>(jwks)))
        // Claim checks happen in Spring's validators below.
        processor.setJWTClaimsSetVerifier { _, _ -> }

        val decoder = NimbusJwtDecoder(processor)
        decoder.setJwtValidator(
            DelegatingOAuth2TokenValidator(
                JwtValidators.createDefaultWithIssuer(issuer), // exp, nbf (60s skew) + iss
                AudienceValidator(audience),
            )
        )
        return decoder
    }

    @Bean
    fun jwtAuthenticationConverter(): JwtAuthenticationConverter {
        val converter = JwtAuthenticationConverter()
        converter.setJwtGrantedAuthoritiesConverter { jwt ->
            val authorities = mutableListOf<GrantedAuthority>()
            val scopes = (jwt.claims["scope"] as? String)?.split(" ")?.filter { it.isNotBlank() } ?: emptyList()
            authorities += scopes.map { SimpleGrantedAuthority("SCOPE_$it") }
            val roles = jwt.claims["roles"] as? Collection<*> ?: emptyList<Any>()
            authorities += roles.map { SimpleGrantedAuthority("ROLE_$it") }
            val permissions = jwt.claims["permissions"] as? Collection<*> ?: emptyList<Any>()
            authorities += permissions.map { SimpleGrantedAuthority(it.toString()) }
            authorities
        }
        return converter
    }

    class AudienceValidator(private val audience: String) : OAuth2TokenValidator<Jwt> {
        override fun validate(token: Jwt): OAuth2TokenValidatorResult =
            if (token.audience?.contains(audience) == true) {
                OAuth2TokenValidatorResult.success()
            } else {
                OAuth2TokenValidatorResult.failure(OAuth2Error("invalid_token", "The required audience is missing", null))
            }
    }

    private fun loadPublicKey(path: String): RSAPublicKey {
        val pem = ClassPathResource(path).inputStream.use { it.readBytes().decodeToString() }
        val der = Base64.getDecoder().decode(pem.lines().filterNot { it.startsWith("-----") }.joinToString(""))
        return KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(der)) as RSAPublicKey
    }
}
