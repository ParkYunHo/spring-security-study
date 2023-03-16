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
@EnableWebSecurity
@Configuration
@Order(1)
class AdminSecurityConfig {
    private val log = LoggerFactory.getLogger(this::class.java)

    /**
     * 다중 설정클래스 설정 (ADMIN용)
     * <p>
     *     - "/admin"으로 FilterChainProxy로 Request가 들어온 경우 해당 RequestMatcher에 매핑됨
     */
    @Bean
    fun configureAdmin(http: HttpSecurity): SecurityFilterChain {
        http
            .authorizeHttpRequests()
                .requestMatchers("/admin/**").authenticated()
                .anyRequest().authenticated()
                .and()
            .httpBasic()

        return http.build()
    }
}