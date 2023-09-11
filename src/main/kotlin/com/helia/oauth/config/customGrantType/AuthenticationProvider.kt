package com.helia.oauth.config.customGrantType

import com.helia.oauth.model.CustomPasswordUser
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.oauth2.core.*
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator
import org.springframework.util.Assert
import java.security.Principal
import java.util.stream.Collectors

class AuthenticationProvider(
    authorizationService: OAuth2AuthorizationService,
    tokenGenerator: OAuth2TokenGenerator<out OAuth2Token>,
    userDetailsService: UserDetailsService
) : AuthenticationProvider {
    private val authorizationService: OAuth2AuthorizationService
    private val userDetailsService: UserDetailsService
    private val tokenGenerator: OAuth2TokenGenerator<out OAuth2Token>
    private var username = ""
    private var password = ""
    private var authorizedScopes: Set<String> = HashSet()

    init {
        Assert.notNull(authorizationService, "authorizationService cannot be null")
        Assert.notNull(tokenGenerator, "TokenGenerator cannot be null")
        Assert.notNull(userDetailsService, "UserDetailsService cannot be null")
        this.authorizationService = authorizationService
        this.tokenGenerator = tokenGenerator
        this.userDetailsService = userDetailsService
    }

    @Throws(AuthenticationException::class)
    override fun authenticate(authentication: Authentication): Authentication {
        val authenticationToken = authentication as AuthenticationToken
        val clientPrincipal = getAuthenticatedClientElseThrowInvalidClient(authenticationToken)
        val registeredClient = clientPrincipal.registeredClient
        username = authenticationToken.username
        password = authenticationToken.password
        var user: User? = null
        user = try {
            userDetailsService.loadUserByUsername(username) as User
        } catch (e: UsernameNotFoundException) {
            throw OAuth2AuthenticationException(OAuth2ErrorCodes.ACCESS_DENIED)
        }
        if (user!!.password != password || user.username != username) {
            throw OAuth2AuthenticationException(OAuth2ErrorCodes.ACCESS_DENIED)
        }
        authorizedScopes = user.authorities.stream()
            .map { scope: GrantedAuthority -> scope.authority }
            .filter { scope: String? -> registeredClient!!.scopes.contains(scope) }
            .collect(Collectors.toSet())

        //-----------Create a new Security Context Holder Context----------
        val oAuth2ClientAuthenticationToken =
            SecurityContextHolder.getContext().authentication as OAuth2ClientAuthenticationToken
        val customPasswordUser = CustomPasswordUser(username, user.authorities)
        oAuth2ClientAuthenticationToken.details = customPasswordUser
        val newcontext = SecurityContextHolder.createEmptyContext()
        newcontext.authentication = oAuth2ClientAuthenticationToken
        SecurityContextHolder.setContext(newcontext)

        //-----------TOKEN BUILDERS----------
        val tokenContextBuilder = DefaultOAuth2TokenContext.builder()
            .registeredClient(registeredClient)
            .principal(clientPrincipal)
            .authorizationServerContext(AuthorizationServerContextHolder.getContext())
            .authorizedScopes(authorizedScopes)
            .authorizationGrantType(AuthorizationGrantType("custom_password"))
            .authorizationGrant(authenticationToken)
        val authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
            .attribute(Principal::class.java.getName(), clientPrincipal)
            .principalName(clientPrincipal.name)
            .authorizationGrantType(AuthorizationGrantType("custom_password"))
            .authorizedScopes(authorizedScopes)

        //-----------ACCESS TOKEN----------
        var tokenContext: OAuth2TokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build()
        val generatedAccessToken = tokenGenerator.generate(tokenContext)
        if (generatedAccessToken == null) {
            val error = OAuth2Error(
                OAuth2ErrorCodes.SERVER_ERROR,
                "The token generator failed to generate the access token.", ERROR_URI
            )
            throw OAuth2AuthenticationException(error)
        }
        val accessToken = OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            generatedAccessToken.tokenValue, generatedAccessToken.issuedAt,
            generatedAccessToken.expiresAt, tokenContext.authorizedScopes
        )
        if (generatedAccessToken is ClaimAccessor) {
            authorizationBuilder.token(accessToken) { metadata: MutableMap<String?, Any?> ->
                metadata[OAuth2Authorization.Token.CLAIMS_METADATA_NAME] =
                    (generatedAccessToken as ClaimAccessor).claims
            }
        } else {
            authorizationBuilder.accessToken(accessToken)
        }

        //-----------REFRESH TOKEN----------
        var refreshToken: OAuth2RefreshToken? = null
        if (registeredClient!!.authorizationGrantTypes.contains(AuthorizationGrantType.REFRESH_TOKEN) &&
            clientPrincipal.clientAuthenticationMethod != ClientAuthenticationMethod.NONE
        ) {
            tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build()
            val generatedRefreshToken = tokenGenerator.generate(tokenContext)
            if (generatedRefreshToken !is OAuth2RefreshToken) {
                val error = OAuth2Error(
                    OAuth2ErrorCodes.SERVER_ERROR,
                    "The token generator failed to generate the refresh token.", ERROR_URI
                )
                throw OAuth2AuthenticationException(error)
            }
            refreshToken = generatedRefreshToken
            authorizationBuilder.refreshToken(refreshToken)
        }
        val authorization = authorizationBuilder.build()
        authorizationService.save(authorization)
        return OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken, refreshToken)
    }

    override fun supports(authentication: Class<*>?): Boolean {
        return AuthenticationToken::class.java.isAssignableFrom(authentication)
    }

    companion object {
        private const val ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2"
        private fun getAuthenticatedClientElseThrowInvalidClient(authentication: Authentication): OAuth2ClientAuthenticationToken {
            var clientPrincipal: OAuth2ClientAuthenticationToken? = null
            if (OAuth2ClientAuthenticationToken::class.java.isAssignableFrom(authentication.principal.javaClass)) {
                clientPrincipal = authentication.principal as OAuth2ClientAuthenticationToken
            }
            if (clientPrincipal != null && clientPrincipal.isAuthenticated) {
                return clientPrincipal
            }
            throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT)
        }
    }
}
