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

    @GetMapping("/loginPage")
    fun loginPage(): String =
        "loginPage"
}