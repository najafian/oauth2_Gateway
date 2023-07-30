package com.helia.oauth.repository

import com.helia.oauth.entity.Role
import org.springframework.data.jpa.repository.JpaRepository

interface RoleRepository : JpaRepository<Role, Long> {
    fun findByRoleCode(roleCode: String?): Role?
}
