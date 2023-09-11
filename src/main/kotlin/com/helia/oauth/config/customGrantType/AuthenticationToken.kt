package com.helia.oauth.config.customGrantType

import org.springframework.lang.Nullable
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken
import java.util.*

class AuthenticationToken(
    clientPrincipal: Authentication?,
    @Nullable scopes: Set<String>?, @Nullable additionalParameters: Map<String, Any>
) : OAuth2AuthorizationGrantAuthenticationToken(
    AuthorizationGrantType("custom_password"),
    clientPrincipal,
    additionalParameters
) {
    val username: String
    val password: String
    val scopes: Set<String>

    init {
        username = additionalParameters["username"] as String
        password = additionalParameters["password"] as String
        this.scopes = Collections.unmodifiableSet(
            scopes?.let { HashSet(it) } ?: emptySet())
    }

    companion object {
        private const val serialVersionUID = 1L
    }
}
