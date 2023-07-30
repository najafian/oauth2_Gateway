package com.helia.oauth.service

import com.helia.oauth.repository.OAuth2ClientRoleRepository
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.user.DefaultOAuth2User
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.util.CollectionUtils

/**
 * Permission mapping service, OAuth2 login users will be given corresponding permissions, if the mapping permission is empty, the lowest permission ROLE_OPERATION will be given
 *
 *
 * Note: `authority` and `role` are custom permission information fields in this example, which are not specified in the OAuth2 protocol and the OpenID Connect protocol
 *
 *
 */

internal class AuthorityMappingOAuth2UserService(private var oAuth2ClientRoleRepository:OAuth2ClientRoleRepository) :
    OAuth2UserService<OAuth2UserRequest, OAuth2User> {
    private val delegate = DefaultOAuth2UserService()

    @Throws(OAuth2AuthenticationException::class)
    override fun loadUser(userRequest: OAuth2UserRequest): OAuth2User {
        val oAuth2User = delegate.loadUser(userRequest) as DefaultOAuth2User
        val additionalParameters = userRequest.additionalParameters
        val role: MutableSet<String> = HashSet()
        if (additionalParameters.containsKey("authority")) {
            role.addAll((additionalParameters["authority"] as Collection<String>?)!!)
        }
        if (additionalParameters.containsKey("role")) {
            role.addAll((additionalParameters["role"] as Collection<String>?)!!)
        }
        var mappedAuthorities = role.map { r ->
            SimpleGrantedAuthority(
                oAuth2ClientRoleRepository.findByClientRegistrationIdAndRoleCode(
                    userRequest.clientRegistration.registrationId,
                    r
                )!!.role!!.roleCode
            )
        }.toSet()
        //When no client role is specified, the least privilege ROLE_OPERATION is given by default
        if (CollectionUtils.isEmpty(mappedAuthorities)) {
            mappedAuthorities = setOf(SimpleGrantedAuthority("ROLE_OPERATION"))
        }
        val userNameAttributeName =
            userRequest.clientRegistration.providerDetails.userInfoEndpoint.userNameAttributeName
        return DefaultOAuth2User(mappedAuthorities, oAuth2User.attributes, userNameAttributeName)
    }
}
