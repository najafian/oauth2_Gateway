package com.helia.oauth.entity

import jakarta.persistence.*

@Entity
@Table(name = "`role`")
class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    var id: Long? = null
    var roleCode: String? = null

    @ManyToMany(cascade = [CascadeType.REFRESH], fetch = FetchType.EAGER)
    @JoinTable(
        name = "role_mtm_permission",
        joinColumns = [JoinColumn(name = "role_id")],
        inverseJoinColumns = [JoinColumn(name = "permission_id")]
    )
    var permissions: MutableList<Permission>? = null
}
