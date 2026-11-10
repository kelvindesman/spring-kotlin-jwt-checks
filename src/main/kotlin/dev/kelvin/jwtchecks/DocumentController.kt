package dev.kelvin.jwtchecks

import org.springframework.http.HttpStatus
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api")
class DocumentController {

    @GetMapping("/documents")
    fun list(): Map<String, Any> = mapOf("documents" to listOf("q3-report.pdf", "contract.docx"))

    @PostMapping("/documents")
    @ResponseStatus(HttpStatus.CREATED)
    fun upload(@RequestBody body: Map<String, String>): Map<String, String> =
        mapOf("saved" to (body["name"] ?: "untitled"))

    @GetMapping("/admin/documents")
    @PreAuthorize("hasRole('admin') and hasAuthority('documents:read:all')")
    fun everything(): Map<String, Any> =
        mapOf("documents" to listOf("q3-report.pdf", "contract.docx", "board-minutes.pdf"))
}
