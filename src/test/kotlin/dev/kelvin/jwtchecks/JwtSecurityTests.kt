package dev.kelvin.jwtchecks

import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.MediaType
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.ResultActions
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.test.web.servlet.setup.DefaultMockMvcBuilder
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.web.context.WebApplicationContext
import java.time.Instant

/**
 * Every test sends a real token through the real decoder. Spring's jwt() test helper
 * skips the decoder, so it can't catch a missing issuer, audience or algorithm check.
 */
@SpringBootTest
class JwtSecurityTests {

    @Autowired
    lateinit var context: WebApplicationContext

    lateinit var mvc: MockMvc

    @BeforeEach
    fun setUp() {
        mvc = MockMvcBuilders.webAppContextSetup(context)
            .apply<DefaultMockMvcBuilder>(springSecurity())
            .build()
    }

    private fun get(path: String, token: String? = null): ResultActions =
        mvc.perform(MockMvcRequestBuilders.get(path).apply { token?.let { header("Authorization", "Bearer $it") } })

    // --- the happy path and basic access control ---

    @Test
    fun `valid token with read scope gets the documents`() {
        get("/api/documents", Tokens.rs256()).andExpect(status().isOk)
    }

    @Test
    fun `no token is 401`() {
        get("/api/documents").andExpect(status().isUnauthorized)
    }

    @Test
    fun `valid token without the read scope is 403`() {
        get("/api/documents", Tokens.rs256(Tokens.claims(scope = "profile"))).andExpect(status().isForbidden)
    }

    @Test
    fun `read scope cannot upload`() {
        mvc.perform(
            MockMvcRequestBuilders.post("/api/documents")
                .header("Authorization", "Bearer ${Tokens.rs256()}")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"name":"notes.txt"}""")
        ).andExpect(status().isForbidden)
    }

    @Test
    fun `write scope can upload`() {
        mvc.perform(
            MockMvcRequestBuilders.post("/api/documents")
                .header("Authorization", "Bearer ${Tokens.rs256(Tokens.claims(scope = "write:documents"))}")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"name":"notes.txt"}""")
        ).andExpect(status().isCreated)
    }

    // --- claim validation ---

    @Test
    fun `expired token is 401`() {
        val token = Tokens.rs256(Tokens.claims(expiresAt = Instant.now().minusSeconds(300)))
        get("/api/documents", token).andExpect(status().isUnauthorized)
    }

    @Test
    fun `token from another issuer is 401`() {
        val token = Tokens.rs256(Tokens.claims(issuer = "https://some-other-app.example"))
        get("/api/documents", token).andExpect(status().isUnauthorized)
    }

    @Test
    fun `token minted for another API is 401`() {
        val token = Tokens.rs256(Tokens.claims(audience = "billing-api"))
        get("/api/documents", token).andExpect(status().isUnauthorized)
    }

    // --- signature and algorithm attacks ---

    @Test
    fun `unsigned alg none token is 401`() {
        get("/api/documents", Tokens.unsigned()).andExpect(status().isUnauthorized)
    }

    @Test
    fun `HS256 signed with the public key is 401`() {
        get("/api/documents", Tokens.hs256WithPublicKey()).andExpect(status().isUnauthorized)
    }

    @Test
    fun `edited payload with the original signature is 401`() {
        val valid = Tokens.rs256(Tokens.claims(scope = "profile"))
        val forged = Tokens.tampered(valid, Tokens.claims(scope = "read:documents write:documents"))
        get("/api/documents", forged).andExpect(status().isUnauthorized)
    }

    // --- key rotation ---

    @Test
    fun `token signed with the previous key still works during rotation`() {
        get("/api/documents", Tokens.rs256(kid = "previous")).andExpect(status().isOk)
    }

    @Test
    fun `token signed with a retired key is 401`() {
        get("/api/documents", Tokens.rs256(kid = "retired")).andExpect(status().isUnauthorized)
    }

    // --- roles and permissions with @PreAuthorize ---

    @Test
    fun `admin with read-all permission sees everything`() {
        val token = Tokens.rs256(Tokens.claims(roles = listOf("admin"), permissions = listOf("documents:read:all")))
        get("/api/admin/documents", token).andExpect(status().isOk)
    }

    @Test
    fun `admin role without the permission is 403`() {
        val token = Tokens.rs256(Tokens.claims(roles = listOf("admin")))
        get("/api/admin/documents", token).andExpect(status().isForbidden)
    }

    @Test
    fun `editor with the permission but not the role is 403`() {
        val token = Tokens.rs256(Tokens.claims(roles = listOf("editor"), permissions = listOf("documents:read:all")))
        get("/api/admin/documents", token).andExpect(status().isForbidden)
    }
}
