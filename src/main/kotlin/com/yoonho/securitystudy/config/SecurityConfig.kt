package com.yoonho.securitystudy.config

import org.slf4j.LoggerFactory
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authorization.AuthorizationManager
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter
import org.springframework.security.web.savedrequest.HttpSessionRequestCache

/**
 * @author yoonho
 * @since 2023.03.08
 */
@Configuration
@EnableWebSecurity
class SecurityConfig(
//    private val userDetailsService: UserDetailsService
) {

    private val log = LoggerFactory.getLogger(this::class.java)

    /**
     * 사용자 생성 및 권한설정
     * <p>
     *     - WebSecurityConfigureAdapter방식은 deprecated 되어 사용자등록시 아래와 같은 방식으로 변경됨
     *     - "withDefaultPasswordEncoder()"방식도 deprecated 되어 "withUsername().password().roles().build()" 방식으로 설정
     *     - password("{noop}1111")에서 "{noop}"는 패스워드를 암호화(인코딩)하는 알고리즘 유형을 prefix 형태로 나타냄
     *      ㄴ 비밀번호 유효성체크시 해당 prefix를 보고 어떠한 알고리즘으로 암호화하였는지 체크하여 유효성로직을 진행함
     *      ㄴ prefix를 설정하지 않으면 password를 "null"로 보고 정상적으로 유효성체크가 진행되지 않음
     *      ㄴ "{noop}"는 별도 암호화하지 않고 평문 그대로를 사용하겠다는 의미
     *
     * @author yoonho
     * @since 2023.03.13
     */
    @Bean
    fun userDetailsService(): InMemoryUserDetailsManager {
        val user1 = User
            .withUsername("user")
            .password("{noop}1111")
            .roles("USER")
            .build()

        val user2 = User
            .withUsername("sys")
            .password("{noop}1111")
            .roles("SYS", "USER")
            .build()

        val user3 = User
            .withUsername("admin")
            .password("{noop}1111")
            .roles("ADMIN", "SYS", "USER")
            .build()

        return InMemoryUserDetailsManager(user1, user2, user3)
    }

    @Bean
    fun configure(http: HttpSecurity): SecurityFilterChain {
        /* ::::::: 로그인Form 설정 ::::::: */
        http
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

                // 인증 Exception시 사용자의 경로,파라미터,header정보 등을 캐시에 저장함. (인증/인가 Exception 참고)
                val requestCache = HttpSessionRequestCache()
                val savedRequest = requestCache.getRequest(request, response)
                val redirectUrl = savedRequest.redirectUrl
                response.sendRedirect(redirectUrl)
                //

//                response.sendRedirect("/")
            }
            // 로그인 실패시 Handler
            .failureHandler { request, response, exception ->
                log.info(" >>> [failureHandler] exception: ${exception.message}")
                response.sendRedirect("/loginPage")
            }
            .permitAll()    // 커스텀로그인페이지는 인증을 받지않아도 접근할 수 있도록 설정

        /* ::::::: 로그아웃 설정 ::::::: */
        http
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

        /* ::::::: RememberMe 설정 ::::::: */
//        http
//            .rememberMe()
//            .rememberMeParameter("remember")    // 체크박스 파라미터명 설정 (default: remember-me)
//            .tokenValiditySeconds(3600)          // RememberMe 쿠키의 TTL (default: 14일)
////            .alwaysRemember(true)                   // RememberMe 기능이 활성화되지 않아도 항상 실행 (rememberMe 체크박스가 활성화 되지 않아도 동작시키는 옵션)
//            .userDetailsService(userDetailsService)                // 실제 인증을 처리하는 서비스

        /* ::::::: 세션관리 설정 ::::::: */
        http
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)   // 세션정책 (default: IF_REQUIRED)
            .maximumSessions(1)                         // 최대 허용가능 세션수 (default: -1 / 무제한 로그인 세션 허용)
            // true: "현재 사용자 인증실패" 방식 / false: "기존 사용자 인증실패" 방식
            .maxSessionsPreventsLogin(false)     // 동시 로그인 차단 옵션 (default: false / 기존 세션 만료)
//            .expiredUrl("/expired")                                  // 세션이 만료된 경우 이동할 페이지
        http
            .sessionManagement()
            .sessionFixation()
            // 세션고정 보호 (none, migrateSession, newSession 옵션이 더 있으나 기본값으로 changeSessionId로 설정됨)
            .changeSessionId()

        /* ::::::: 권한설정(인가) ::::::: */
        http
            /*
                WebSecurityConfigureAdapter가 deprecated 되어 상세메서드가 변경됨
                 - .authorizeRequests() -> .authorizeHttpRequests()
                 - .antMatchers() -> .requestMatchers()
                 - .access("hasAnyRole('USER', 'ADMIN')") -> .hasAnyRole("USER", "ADMIN")
                 requestMatchers는 위에 설정한 경로부터 체크하므로 "구체적인 경로"를 먼저 설정하고 "큰 범위의 경로"를 뒤에 설정해야 한다.
             */
            .authorizeHttpRequests()
            // 인강방식대로 설정
            .requestMatchers("/user").hasRole("USER")
            .requestMatchers("/admin/pay").hasRole("ADMIN")
            .requestMatchers("/admin/**").hasAnyRole("ADMIN", "SYS")

            // 강의자료 방식대로 설정
            .requestMatchers("/shop/login", "/shop/users/**").permitAll()
            .requestMatchers("/shop/mypage").hasRole("USER")
            .requestMatchers("/shop/admin/pay").hasAnyRole("ADMIN")
            .requestMatchers("/shop/admin/**").hasAnyRole("ADMIN", "SYS")

            // 인증실패시 redirect 할 커스텀 로그인페이지에 대해 인증을 허용함
//            .requestMatchers("/login").permitAll()
            .anyRequest().authenticated()

        /* ::::::: 인증/인가 Exception 설정 ::::::: */
        http
            .exceptionHandling()
                // 인증실패시 ExceptionHandler
                .authenticationEntryPoint { request, response, authException ->
                    // Spring Security에서 제공하는 로그인페이지가 아닌 Custom 로그인페이지로 이동됨.
                    response.sendRedirect("/login")
                }
                // 인가실패시 ExceptionHandler
                .accessDeniedHandler { request, response, accessDeniedException ->
                    // Spring Security에서 제공하는 Denied페이지가 아닌 Custom Denied페이지로 이동됨.
                    response.sendRedirect("/denied")
                }

        return http.build()
    }
}