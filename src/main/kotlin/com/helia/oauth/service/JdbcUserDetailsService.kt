package com.helia.oauth.service

import com.helia.oauth.repository.UserRepository
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.util.CollectionUtils
import org.springframework.util.ObjectUtils
import java.util.stream.Collectors

/**
 * User service, used to obtain user information during Form authentication
 *
 */

class JdbcUserDetailsService(private val userRepository: UserRepository) : UserDetailsService {
    override fun loadUserByUsername(username: String): UserDetails {
        val user= userRepository.findUserByUsername(username)!!
        if (ObjectUtils.isEmpty(user)) {
            throw UsernameNotFoundException("user is not found")
        }
        if (CollectionUtils.isEmpty(user.roleList)) {
            throw UsernameNotFoundException("role is not found")
        }
        val authorities: Set<SimpleGrantedAuthority> = user.roleList!!.map { SimpleGrantedAuthority(it.roleCode) }.toSet()
        return User(user.username, user.password, authorities)
    }
}
