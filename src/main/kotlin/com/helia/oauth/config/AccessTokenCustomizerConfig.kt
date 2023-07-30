package com.helia.oauth.config

import com.helia.oauth.repository.RoleRepository
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer
import java.util.function.Consumer

/**
 * Custom Access Token
 *
 *
 * This example uses the RBAC0 permission model to query the corresponding permissions of the role based on the obtained role information in the security context, add the permission to the access token, and replace the original value in the scope.
 *
 *
 */
@Configuration(proxyBeanMethods = false)
class AccessTokenCustomizerConfig(var roleRepository: RoleRepository) {
    @Bean
    fun tokenCustomizer(): OAuth2TokenCustomizer<JwtEncodingContext> {
        return OAuth2TokenCustomizer<JwtEncodingContext> { context: JwtEncodingContext ->
            if (OAuth2TokenType.ACCESS_TOKEN == context.tokenType) {
                context.claims.claims(Consumer<MutableMap<String?, Any?>> { claim: MutableMap<String?, Any?> ->
                    claim["authorities"] =
                        roleRepository.findByRoleCode(context.getPrincipal<Authentication>().authorities.stream()
                            .map { obj: GrantedAuthority -> obj.authority }.findFirst()
                            .orElse("ROLE_OPERATION")
                        )!!.permissions!!.map { it.permissionCode }.toSet()
                })
            }
        }
    }
}
