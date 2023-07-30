package com.helia.oauth.config

import com.helia.oauth.jose.Jwks.generateRsa
import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer.AuthorizationManagerRequestMatcherRegistry
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import java.time.Duration

/**
 * OAuth2 and OpenID Connect Configuration
 *
 */
@Configuration(proxyBeanMethods = false)
internal class AuthorizationServerConfig {
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    @Throws(
        Exception::class
    )
    fun authorizationServerSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        val authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer()
        //Configure OIDC
        authorizationServerConfigurer.oidc(Customizer.withDefaults())
        val endpointsMatcher = authorizationServerConfigurer.endpointsMatcher
        return http.securityMatcher(endpointsMatcher)
            .authorizeHttpRequests { authorizeRequests ->
                authorizeRequests.anyRequest().authenticated()
            }.csrf { csrf: CsrfConfigurer<HttpSecurity?> -> csrf.ignoringRequestMatchers(endpointsMatcher) }
            .apply(authorizationServerConfigurer)
            .and()
            .oauth2ResourceServer { obj: OAuth2ResourceServerConfigurer<HttpSecurity?> -> obj.jwt() }
            .exceptionHandling { exceptions: ExceptionHandlingConfigurer<HttpSecurity?> ->
                exceptions.authenticationEntryPoint(
                    LoginUrlAuthenticationEntryPoint("/login")
                )
            }
            .apply(authorizationServerConfigurer)
            .and()
            .build()
    }

    /**
     * Persistent OAuth2 Client
     *
     * @param jdbcTemplate
     * @return
     */
    @Bean
    fun registeredClientRepository(jdbcTemplate: JdbcTemplate?): RegisteredClientRepository {
        val registeredClient = RegisteredClient.withId("relive-messaging-oidc")
            .clientId("relive-client")
            .clientSecret("{noop}relive-client")
            .clientAuthenticationMethods { s: MutableSet<ClientAuthenticationMethod?> ->
                s.add(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                s.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            }
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .redirectUri("http://127.0.0.1:8070/login/oauth2/code/messaging-gateway-oidc")
            .scope(OidcScopes.OPENID)
            .scope(OidcScopes.PROFILE)
            .scope(OidcScopes.EMAIL)
            .scope("read")
            .clientSettings(
                ClientSettings.builder()
                    .requireAuthorizationConsent(false) //No authorization required
                    .requireProofKey(false)
                    .build()
            )
            .tokenSettings(
                TokenSettings.builder()
                    .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED) // Generate JWT token
                    .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256) //idTokenSignatureAlgorithm：signature algorithm
                    .accessTokenTimeToLive(Duration.ofSeconds((30 * 60).toLong())) //accessTokenTimeToLive: access_token validity period
                    .refreshTokenTimeToLive(Duration.ofSeconds((60 * 60).toLong())) //refreshTokenTimeToLive: refresh_token validity period
                    .reuseRefreshTokens(true) //reuseRefreshTokens: Whether to reuse refresh tokens
                    .build()
            )
            .build()
        val registeredClientRepository = JdbcRegisteredClientRepository(jdbcTemplate)
        registeredClientRepository.save(registeredClient)
        return registeredClientRepository
    }

    /**
     * Responsible for persisting authorization information during the authorization process, such as code, access_token, refresh_token
     *
     * @param jdbcTemplate
     * @param registeredClientRepository
     * @return
     */
    @Bean
    fun authorizationService(
        jdbcTemplate: JdbcTemplate?,
        registeredClientRepository: RegisteredClientRepository?
    ): OAuth2AuthorizationService {
        return JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository)
    }

    /**
     * Persistent user consent "authorization consent" information
     *
     * @param jdbcTemplate
     * @param registeredClientRepository
     * @return
     */
    @Bean
    fun authorizationConsentService(
        jdbcTemplate: JdbcTemplate?,
        registeredClientRepository: RegisteredClientRepository?
    ): OAuth2AuthorizationConsentService {
        return JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository)
    }

    @Bean
    fun authorizationServerSettings(): AuthorizationServerSettings {
        return AuthorizationServerSettings.builder()
            .issuer("http://127.0.0.1:8080")
            .build()
    }

    @Bean
    fun jwkSource(): JWKSource<SecurityContext> {
        val rsaKey = generateRsa()
        val jwkSet = JWKSet(rsaKey)
        return JWKSource { jwkSelector: JWKSelector, securityContext: SecurityContext? -> jwkSelector.select(jwkSet) }
    }

    @Bean
    fun jwtDecoder(jwkSource: JWKSource<SecurityContext?>?): JwtDecoder {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)
    }
}
