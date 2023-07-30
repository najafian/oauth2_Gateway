package com.helia.oauth.entity

import jakarta.persistence.*

@Entity
@Table(name = "`oauth2_client_role`")
class OAuth2ClientRole {
    @Id
    var id: Long? = null
    var clientRegistrationId: String? = null
    var roleCode: String? = null

    @ManyToOne
    @JoinTable(
        name = "oauth2_client_role_mapping",
        joinColumns = [JoinColumn(name = "oauth_client_role_id")],
        inverseJoinColumns = [JoinColumn(name = "role_id")]
    )
    var role: Role? = null
}
