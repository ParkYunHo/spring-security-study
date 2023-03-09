package com.yoonho.securitystudy.config

import org.slf4j.LoggerFactory
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter

/**
 * @author yoonho
 * @since 2023.03.08
 */
@Configuration
@EnableWebSecurity
class SecurityConfig(
    private val userDetailsService: UserDetailsService
) {

    private val log = LoggerFactory.getLogger(this::class.java)

    @Bean
    fun configure(http: HttpSecurity): SecurityFilterChain =
        http
            /* ::::::: 로그인Form 설정 ::::::: */
            .formLogin()
//                .loginPage("/loginPage")                    // 커스텀 로그인페이지
                .defaultSuccessUrl("/")               // 로그인성공시 이동할 경로
                .failureUrl("/login")             // 로그인실패시 이동할 경로
                // Custom LoginPage 생성시 tag id를 아래 설정한 값과 동일하게 맞춰주어야 한다.
                .usernameParameter("userId")         // "username" 파라미터 커스텀 명칭 (HTML Tag id)
                .passwordParameter("passwd")         // "password" 파라미터 커스텀 명칭 (HTML Tag id)
                //
                .loginProcessingUrl("/login_proc")    // 로그인 프로세스를 처리할 경로
                // 로그인 성공시 Handler
                .successHandler { request, response, authentication ->
                    log.info(" >>> [successHandler] authentication: ${authentication.name}")
                    response.sendRedirect("/")
                }
                // 로그인 실패시 Handler
                .failureHandler { request, response, exception ->
                    log.info(" >>> [failureHandler] exception: ${exception.message}")
                    response.sendRedirect("/loginPage")
                }
                .permitAll()    // 커스텀로그인페이지는 인증을 받지않아도 접근할 수 있도록 설정
                .and()

            /* ::::::: 로그아웃 설정 ::::::: */
            .logout()
                .logoutUrl("/logout")   // 기본적으로 POST방식으로 처리됨
                .logoutSuccessUrl("/login")
                // Spring Security에서는 기본적으로 LogoutHandler를 제공하나, 별도 추가적인 처리가 필요한 경우 설정
                .addLogoutHandler { request, response, authentication ->
                    val session = request.session
                    session.invalidate()    // 세션 무효화처리
                }
                // logoutSuccessUrl과 동작은 유사하나 "Url"에서는 url이동액션만 가능하고, "Handler"에서는 다양한 동작가능
                .logoutSuccessHandler { request, response, authentication ->
                    response.sendRedirect("/login")
                }
                // 로그아웃시 삭제하고자하는 쿠키 설정
                .deleteCookies("remember-me")
                .and()

            /* ::::::: RememberMe 설정 ::::::: */
            .rememberMe()
                .rememberMeParameter("remember")    // 체크박스 파라미터명 설정 (default: remember-me)
                .tokenValiditySeconds(3600)          // RememberMe 쿠키의 TTL (default: 14일)
                .alwaysRemember(true)                   // RememberMe 기능이 활성화되지 않아도 항상 실행 (rememberMe 체크박스가 활성화 되지 않아도 동작시키는 옵션)
                .userDetailsService(userDetailsService)                // 실제 인증을 처리하는 서비스
                .and()

            .authorizeHttpRequests()
                .anyRequest().authenticated()
                .and()
            .build()


//    @Bean
//    fun configure(http: HttpSecurity): SecurityFilterChain =
//        http
//            .formLogin()
//                .loginPage("/login")
//                .permitAll()
//                .and()
//            .httpBasic().disable()
//            .csrf().disable()
//            .authorizeHttpRequests()
//                .requestMatchers("/").permitAll()
//                .requestMatchers("/login/register").permitAll()
//                .requestMatchers("/resources/**", "/static/**", "/css/**", "/js/**").permitAll()
//                .anyRequest().authenticated()
//                .and()
//            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//                .and()
//            // H2 Console 허용
//            .headers()
//                .addHeaderWriter(XFrameOptionsHeaderWriter(XFrameOptionsHeaderWriter.XFrameOptionsMode.SAMEORIGIN))
//                .and()
//            .build()
}