package com.yoonho.securitystudy.controller

import jakarta.servlet.http.HttpSession
import org.slf4j.LoggerFactory
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.context.HttpSessionSecurityContextRepository
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

/**
 * @author yoonho
 * @since 2023.03.08
 */
@RestController
class HomeController {
    private val log = LoggerFactory.getLogger(this::class.java)

    @GetMapping("/")
    fun index(session: HttpSession): String {

        // SecurityContextHolder로부터 인증정보 획득
        val auth: Authentication = SecurityContextHolder.getContext().authentication

        // 세션에 저장된 SecurityContext 획득
        val context: SecurityContext = session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY) as SecurityContext
        val authBySession: Authentication = context.authentication

        return "home"
    }

    @GetMapping("/thread")
    fun thread(): String {
        Thread {
            val auth: Authentication = SecurityContextHolder.getContext().authentication
            log.info(" >>> [thread] auth: $auth")
        }.start()

        return "thread"
    }

    @GetMapping("/login")
    fun login(): String =
        "login"

    @GetMapping("/denied")
    fun denied(): String =
        "denied"

    @GetMapping("/loginPage")
    fun loginPage(): String =
        "loginPage"

    @GetMapping("/user")
    fun user(): String =
        "user"

    @GetMapping("/admin/pay")
    fun adminPay(): String =
        "adminPay"

    @GetMapping("/admin/**")
    fun admin(): String =
        "admin"
}