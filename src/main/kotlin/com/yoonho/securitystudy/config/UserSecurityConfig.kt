package com.yoonho.securitystudy.config

import org.slf4j.LoggerFactory
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.web.SecurityFilterChain

/**
 * @author yoonho
 * @since 2023.03.16
 */
@Configuration
@Order(0)
class UserSecurityConfig {
    private val log = LoggerFactory.getLogger(this::class.java)

    /**
     * 다중 설정클래스 설정 (ADMIN용)
     * <p>
     *     - "/admin"으로 FilterChainProxy로 Request가 들어온 경우 해당 RequestMatcher에 매핑됨
     */
    @Bean
    fun configureUser(http: HttpSecurity): SecurityFilterChain {
        http
            .authorizeHttpRequests()
            .anyRequest().permitAll()
            .and()
            .formLogin()

        return http.build()
    }
}