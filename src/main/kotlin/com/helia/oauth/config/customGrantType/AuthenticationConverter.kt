package com.helia.oauth.config.customGrantType

import jakarta.servlet.http.HttpServletRequest
import org.springframework.lang.Nullable
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.web.authentication.AuthenticationConverter
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap
import org.springframework.util.StringUtils
import java.util.*

class AuthenticationConverter :
    AuthenticationConverter {
    @Nullable
    override fun convert(request: HttpServletRequest): Authentication? {
        val grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE)
        if ("custom_password" != grantType) {
            return null
        }
        val parameters = getParameters(request)

        // scope (OPTIONAL)
        val scope = parameters.getFirst(OAuth2ParameterNames.SCOPE)
        if (StringUtils.hasText(scope) &&
            parameters[OAuth2ParameterNames.SCOPE]!!.size != 1
        ) {
            throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST)
        }

        // username (REQUIRED)
        val username = parameters.getFirst(OAuth2ParameterNames.USERNAME)
        if (!StringUtils.hasText(username) ||
            parameters[OAuth2ParameterNames.USERNAME]!!.size != 1
        ) {
            throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST)
        }

        // password (REQUIRED)
        val password = parameters.getFirst(OAuth2ParameterNames.PASSWORD)
        if (!StringUtils.hasText(password) ||
            parameters[OAuth2ParameterNames.PASSWORD]!!.size != 1
        ) {
            throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST)
        }
        var requestedScopes: Set<String>? = null
        if (StringUtils.hasText(scope)) {
            requestedScopes = HashSet(
                Arrays.asList(*StringUtils.delimitedListToStringArray(scope, " "))
            )
        }
        val additionalParameters: MutableMap<String, Any> = HashMap()
        parameters.forEach { (key: String, value: List<String>) ->
            if (key != OAuth2ParameterNames.GRANT_TYPE &&
                key != OAuth2ParameterNames.SCOPE
            ) {
                additionalParameters[key] = value[0]
            }
        }
        val clientPrincipal = SecurityContextHolder.getContext().authentication
        return AuthenticationToken(clientPrincipal, requestedScopes, additionalParameters)
    }

    companion object {
        private fun getParameters(request: HttpServletRequest): MultiValueMap<String, String> {
            val parameterMap = request.parameterMap
            val parameters: MultiValueMap<String, String> = LinkedMultiValueMap(parameterMap.size)
            parameterMap.forEach { (key: String, values: Array<String?>) ->
                if (values.size > 0) {
                    for (value in values) {
                        parameters.add(key, value)
                    }
                }
            }
            return parameters
        }
    }
}
