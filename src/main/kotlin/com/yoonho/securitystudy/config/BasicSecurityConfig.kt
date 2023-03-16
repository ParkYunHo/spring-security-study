package com.yoonho.securitystudy.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.SecurityFilterChain

/**
 * @author yoonho
 * @since 2023.03.16
 */
@Configuration
@EnableWebSecurity
class BasicSecurityConfig {

    @Bean
    fun configure(http: HttpSecurity): SecurityFilterChain {
        http
            .authorizeHttpRequests()
            .anyRequest().authenticated()

        http
            .formLogin()

        // SecurityContextHolder에서 SecurityContext저장방식 변경
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL)

        return http.build()
    }
}