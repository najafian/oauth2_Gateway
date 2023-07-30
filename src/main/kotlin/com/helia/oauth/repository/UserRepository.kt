package com.helia.oauth.repository

import com.helia.oauth.entity.User
import org.springframework.data.jpa.repository.JpaRepository

interface UserRepository : JpaRepository<User, Long> {
    fun findUserByUsername(username: String?): User?
}
