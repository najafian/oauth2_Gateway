package com.helia.oauth.config.customGrantType

import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient

class OAuth2ClientAuthenticationToken :
    OAuth2ClientAuthenticationToken {
    constructor(
        clientId: String?,
        clientAuthenticationMethod: ClientAuthenticationMethod?, credentials: Any?,
        additionalParameters: Map<String?, Any?>?
    ) : super(clientId, clientAuthenticationMethod, credentials, additionalParameters)

    constructor(
        registeredClient: RegisteredClient?,
        clientAuthenticationMethod: ClientAuthenticationMethod?, credentials: Any?
    ) : super(registeredClient, clientAuthenticationMethod, credentials)

    companion object {
        private const val serialVersionUID = 1L
    }
}
