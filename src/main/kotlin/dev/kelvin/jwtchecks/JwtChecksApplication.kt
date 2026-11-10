package dev.kelvin.jwtchecks

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class JwtChecksApplication

fun main(args: Array<String>) {
    runApplication<JwtChecksApplication>(*args)
}
