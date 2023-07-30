package com.helia.oauth.repository

import com.helia.oauth.entity.OAuth2ClientRole
import org.springframework.data.jpa.repository.JpaRepository

interface OAuth2ClientRoleRepository : JpaRepository<OAuth2ClientRole, Long> {
    fun findByClientRegistrationIdAndRoleCode(clientRegistrationId: String, roleCode: String): OAuth2ClientRole?
}
