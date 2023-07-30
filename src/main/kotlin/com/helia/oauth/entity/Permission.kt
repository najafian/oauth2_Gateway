package com.helia.oauth.entity

import jakarta.persistence.*

@Entity
@Table(name = "`permission`")
class Permission {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    var id: Long? = null
    var permissionName: String? = null
    var permissionCode: String? = null
}
