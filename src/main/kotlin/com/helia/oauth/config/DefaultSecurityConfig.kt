package com.helia.oauth.config

import com.helia.oauth.repository.JdbcClientRegistrationRepository
import com.helia.oauth.repository.OAuth2ClientRoleRepository
import com.helia.oauth.repository.UserRepository
import com.helia.oauth.service.AuthorityMappingOAuth2UserService
import com.helia.oauth.service.JdbcUserDetailsService
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.oauth2.client.JdbcOAuth2AuthorizedClientService
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.security.web.SecurityFilterChain

/**
 * Default Spring Web Security Configuration
 *
 */
@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
class DefaultSecurityConfig(var userHandler: UserRepositoryOAuth2UserHandler) {


    @Bean
    @Throws(Exception::class)
    fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .authorizeHttpRequests { authorizeRequests ->
                authorizeRequests.anyRequest().authenticated()
            }
            .formLogin(Customizer.withDefaults<FormLoginConfigurer<HttpSecurity>>())
            .oauth2Login { oauth2login ->
                val successHandler = SavedUserAuthenticationSuccessHandler()
                successHandler.setOauth2UserHandler(userHandler)
                oauth2login.successHandler(successHandler)
            }
        return http.build()
    }

    /**
     * User information container class, used to obtain user information during Form authentication.
     *
     * @param userRepository
     * @return
     */
    @Bean
    fun userDetailsService(userRepository: UserRepository): UserDetailsService {
        return JdbcUserDetailsService(userRepository)
    }

    /**
     * Extended OAuth2 login mapping permission information.
     *
     * @param oAuth2ClientRoleRepository
     * @return
     */
    @Bean
    fun auth2UserService(oAuth2ClientRoleRepository: OAuth2ClientRoleRepository): OAuth2UserService<OAuth2UserRequest, OAuth2User> {
        return AuthorityMappingOAuth2UserService(oAuth2ClientRoleRepository)
    }

    /**
     * Persistent GitHub Client.
     *
     * @param jdbcTemplate
     * @return
     */
    @Bean
    fun clientRegistrationRepository(jdbcTemplate: JdbcTemplate): ClientRegistrationRepository {
        val jdbcClientRegistrationRepository = JdbcClientRegistrationRepository(jdbcTemplate)
        //Please apply for the correct clientId and clientSecret on gmail
        val clientRegistration = ClientRegistration.withRegistrationId("google")
            .clientId("123456")
            .clientSecret("123456")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("{baseUrl}/{action}/oauth2/code/{registrationId}")
            .scope("read:user")
            .authorizationUri("https://gmail.com/login/oauth/authorize")
            .tokenUri("https://gmail.com/login/oauth/access_token")
            .userInfoUri("https://api.gmail.com/user")
            .userNameAttributeName("login")
            .clientName("Google").build()
        jdbcClientRegistrationRepository.save(clientRegistration)
        return jdbcClientRegistrationRepository
    }

    /**
     * Responsible for OAuth2AuthorizedClient persistence between web requests.
     *
     * @param jdbcTemplate
     * @param clientRegistrationRepository
     * @return
     */
    @Bean
    fun authorizedClientService(
        jdbcTemplate: JdbcTemplate?,
        clientRegistrationRepository: ClientRegistrationRepository?
    ): OAuth2AuthorizedClientService {
        return JdbcOAuth2AuthorizedClientService(jdbcTemplate, clientRegistrationRepository)
    }

    /**
     * Used to save and persist authorized clients between requests.
     *
     * @param authorizedClientService
     * @return
     */
    @Bean
    fun authorizedClientRepository(
        authorizedClientService: OAuth2AuthorizedClientService?
    ): OAuth2AuthorizedClientRepository {
        return AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService)
    }
}
