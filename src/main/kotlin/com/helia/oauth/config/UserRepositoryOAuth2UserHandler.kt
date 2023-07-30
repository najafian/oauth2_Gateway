package com.helia.oauth.config

import com.helia.oauth.entity.User
import com.helia.oauth.repository.RoleRepository
import com.helia.oauth.repository.UserRepository
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.oauth2.core.user.DefaultOAuth2User
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.stereotype.Component
import java.util.function.Consumer

/**
 * Persist OAuth2 Login User to User Information Table
 *
 */
@Component
class UserRepositoryOAuth2UserHandler(private val userRepository: UserRepository,private val roleRepository: RoleRepository) : Consumer<OAuth2User> {


    override fun accept(oAuth2User: OAuth2User) {
        val defaultOAuth2User: DefaultOAuth2User = oAuth2User as DefaultOAuth2User
        if (userRepository.findUserByUsername(oAuth2User.getName()) == null) {
            val user = User()
            user.username=defaultOAuth2User.name
            val role = roleRepository.findByRoleCode(defaultOAuth2User.authorities
                .stream().map { obj: GrantedAuthority -> obj.authority }.findFirst()
                .orElse("ROLE_OPERATION")
            )
            user.roleList= mutableListOf(role!!)
            userRepository.save(user)
        }
    }
}
