package com.helia.oauth.config

import com.helia.oauth.model.CustomPasswordUser
import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.password.NoOpPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.OAuth2Token
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2TokenEndpointConfigurer
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OidcConfigurer
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.time.Duration
import java.util.*
import java.util.function.Consumer
import java.util.stream.Collectors

@Suppress("deprecation")
@Configuration
class AuthorizationServerConfig(
    private val userDetailsService: UserDetailsService
) {
    @Bean
    @Order(1)
    @Throws(Exception::class)
    fun asSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http)
        return http.csrf { it.disable() }
            .getConfigurer(OAuth2AuthorizationServerConfigurer::class.java)
            .tokenEndpoint { tokenEndpoint: OAuth2TokenEndpointConfigurer ->
                tokenEndpoint
                    .accessTokenRequestConverter(com.helia.oauth.config.customGrantType.AuthenticationConverter())
                    .authenticationProvider(
                        com.helia.oauth.config.customGrantType.AuthenticationProvider(
                            authorizationService(),
                            tokenGenerator(),
                            userDetailsService
                        )
                    )
                    .accessTokenRequestConverters(getConverters())
                    .authenticationProviders(providers)
            }
            .oidc(Customizer.withDefaults<OidcConfigurer>())
            .and()
            .exceptionHandling(Customizer<ExceptionHandlingConfigurer<HttpSecurity?>> { e: ExceptionHandlingConfigurer<HttpSecurity?> ->
                e
                    .authenticationEntryPoint(LoginUrlAuthenticationEntryPoint("/login"))
            })
            .oauth2ResourceServer(Customizer<OAuth2ResourceServerConfigurer<HttpSecurity?>> { obj: OAuth2ResourceServerConfigurer<HttpSecurity?> -> obj.jwt() })
            .build()
    }

    private val providers: Consumer<List<org.springframework.security.authentication.AuthenticationProvider?>>
        private get() = Consumer { a: List<org.springframework.security.authentication.AuthenticationProvider?> ->
            a.forEach(
                Consumer { x: org.springframework.security.authentication.AuthenticationProvider? -> println(x) })
        }

    private fun getConverters(): Consumer<List<org.springframework.security.web.authentication.AuthenticationConverter?>> {
        return Consumer { a: List<org.springframework.security.web.authentication.AuthenticationConverter?> ->
            a.forEach(
                Consumer { x: org.springframework.security.web.authentication.AuthenticationConverter? -> println(x) })
        }
    }

    @Bean
    @Order(2)
    @Throws(Exception::class)
    fun appSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        return http
            .formLogin(Customizer.withDefaults<FormLoginConfigurer<HttpSecurity>>())
            .authorizeHttpRequests { authorize ->
                authorize.anyRequest().authenticated()
            }
            .build()
    }

    @Bean
    fun authorizationService(): OAuth2AuthorizationService {
        return InMemoryOAuth2AuthorizationService()
    }

    @Bean
    fun oAuth2AuthorizationConsentService(): OAuth2AuthorizationConsentService {
        return InMemoryOAuth2AuthorizationConsentService()
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder {
        return NoOpPasswordEncoder.getInstance()
    }

    @Bean
    fun registeredClientRepository(): RegisteredClientRepository {
        val registeredClient: RegisteredClient = RegisteredClient.withId("relive-messaging-oidc")
            .clientId("relive-client")
            .clientSecret("relive-client")
            .scope("read")
            .scope(OidcScopes.OPENID)
            .scope(OidcScopes.PROFILE)
            .scope(OidcScopes.EMAIL)
            .scope("message.read")
            .scope("message.write")
            .scope("read")
            .redirectUri("http://172.17.0.1:8070/login/oauth2/code/messaging-gateway-oidc")
//            .redirectUri("http://insomnia")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
            .authorizationGrantType(AuthorizationGrantType("custom_password"))
            .tokenSettings(tokenSettings())
            .clientSettings(clientSettings())
            .build()
        return InMemoryRegisteredClientRepository(registeredClient)
    }

    @Bean
    fun tokenSettings(): TokenSettings {
        return TokenSettings.builder()
            .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
            .accessTokenTimeToLive(Duration.ofDays(1))
            .build()
    }

    @Bean
    fun clientSettings(): ClientSettings {
        return ClientSettings.builder().build()
    }

    @Bean
    fun authorizationServerSettings(): AuthorizationServerSettings {
        return AuthorizationServerSettings.builder().issuer("http://172.17.0.1:8080").build()
    }

    @Bean
    fun tokenGenerator(): OAuth2TokenGenerator<out OAuth2Token?> {
        val jwtEncoder = NimbusJwtEncoder(jwkSource())
        val jwtGenerator = JwtGenerator(jwtEncoder)
        jwtGenerator.setJwtCustomizer(tokenCustomizer())
        val accessTokenGenerator = OAuth2AccessTokenGenerator()
        val refreshTokenGenerator = OAuth2RefreshTokenGenerator()
        return DelegatingOAuth2TokenGenerator(
            jwtGenerator, accessTokenGenerator, refreshTokenGenerator
        )
    }

    @Bean
    fun tokenCustomizer(): OAuth2TokenCustomizer<JwtEncodingContext> {
        return OAuth2TokenCustomizer<JwtEncodingContext> { context: JwtEncodingContext ->
            val principal = context.getPrincipal<Authentication>()
            if (principal is OAuth2ClientAuthenticationToken) {
                oauth2ClientGrantTypeJwt(context)
            } else if (principal is UsernamePasswordAuthenticationToken) {
                userAndPasswordViaLoginPage(context)
            }

        }
    }

    fun oauth2ClientGrantTypeJwt(context: JwtEncodingContext) {
        val principal: OAuth2ClientAuthenticationToken = context.getPrincipal()
        val user: CustomPasswordUser = principal.details as CustomPasswordUser
        val authorities: Set<String> = user.authorities().stream()
            .map { obj: GrantedAuthority -> obj.authority }
            .collect(Collectors.toSet())
        if (context.tokenType.value == "access_token") {
            context.claims.claim("authorities", authorities)
                .claim("user", user.username())
        }
    }

    fun userAndPasswordViaLoginPage(context: JwtEncodingContext) {
        val principal = context.getPrincipal<UsernamePasswordAuthenticationToken>().principal
        val user = principal as User
        val authorities: Set<String> = user.authorities
            .map { obj: GrantedAuthority -> obj.authority }.toSet()
        if (context.tokenType.value == "access_token") {
            context.claims.claim("authorities", authorities)
                .claim("user", user.username)
        }
    }

    @Bean
    fun jwtDecoder(jwkSource: JWKSource<SecurityContext?>?): JwtDecoder {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)
    }

    @Bean
    fun jwkSource(): JWKSource<SecurityContext> {
        val rsaKey = generateRsa()
        val jwkSet = JWKSet(rsaKey)
        return JWKSource<SecurityContext> { jwkSelector: JWKSelector, securityContext: SecurityContext? ->
            jwkSelector.select(
                jwkSet
            )
        }
    }

    companion object {
        private fun generateRsa(): RSAKey {
            val keyPair = generateRsaKey()
            val publicKey = keyPair.public as RSAPublicKey
            val privateKey = keyPair.private as RSAPrivateKey
            return RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build()
        }

        private fun generateRsaKey(): KeyPair {
            val keyPair: KeyPair
            keyPair = try {
                val keyPairGenerator: KeyPairGenerator = KeyPairGenerator.getInstance("RSA")
                keyPairGenerator.initialize(2048)
                keyPairGenerator.generateKeyPair()
            } catch (ex: Exception) {
                throw IllegalStateException(ex)
            }
            return keyPair
        }
    }
}
