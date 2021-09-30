package br.com.fairie.springadminserver.security

import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.builders.WebSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler
import org.springframework.security.web.csrf.CookieCsrfTokenRepository
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import java.util.*


@EnableWebSecurity
@Configuration
open class SecurityConfiguration : WebSecurityConfigurerAdapter() {

    @Value("\${credentials.admin.username}")
    private lateinit var adminUsername: String

    @Value("\${credentials.admin.password}")
    private lateinit var adminPassword: String

    @Value("\${credentials.admin.authority}")
    private lateinit var adminAuthority: String

    @Value("\${credentials.client.username}")
    private lateinit var clientUsername: String

    @Value("\${credentials.client.password}")
    private lateinit var clientPassword: String

    @Value("\${credentials.client.authority}")
    private lateinit var clientAuthority: String

    override fun configure(auth: AuthenticationManagerBuilder) {
        auth.inMemoryAuthentication()
            .withUser(adminUsername).password(BCryptPasswordEncoder().encode(adminPassword)).authorities(adminAuthority)
            .and()
            .withUser(clientUsername).password(BCryptPasswordEncoder().encode(clientPassword)).authorities(clientAuthority)
    }

    override fun configure(web: WebSecurity?) {
        super.configure(web)
    }

    override fun configure(http: HttpSecurity) {
        val successHandler = SavedRequestAwareAuthenticationSuccessHandler()
        successHandler.setTargetUrlParameter("redirectTo")
        successHandler.setDefaultTargetUrl("/")

        http
            .authorizeRequests()
            .antMatchers("/assets/**").permitAll()
            .antMatchers("/login").permitAll()
            .anyRequest().authenticated()
            .and()
            .formLogin()
            .loginPage("/login")
            .successHandler(successHandler)
            .and()
            .logout()
            .logoutUrl("/logout")
            .and()
            .httpBasic()
            .and()
            .csrf()
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            .ignoringRequestMatchers(
                AntPathRequestMatcher(
                    "/instances", HttpMethod.POST.toString()
                ),
                AntPathRequestMatcher(
                    "/instances/*", HttpMethod.DELETE.toString()
                ),
                AntPathRequestMatcher("/actuator/**")
            )
            .and()
            .rememberMe()
            .key(UUID.randomUUID().toString())
            .tokenValiditySeconds(1800)
    }

    @Bean
    open fun passwordEncoder(): BCryptPasswordEncoder? {
        return BCryptPasswordEncoder()
    }
}