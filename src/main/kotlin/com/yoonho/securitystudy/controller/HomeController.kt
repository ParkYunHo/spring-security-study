package com.yoonho.securitystudy.controller

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

/**
 * @author yoonho
 * @since 2023.03.08
 */
@RestController
class HomeController {

    @GetMapping("/")
    fun index(): String =
        "home"

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