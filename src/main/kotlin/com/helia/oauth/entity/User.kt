package com.helia.oauth.entity

import jakarta.persistence.*

@Entity
@Table(name = "`user`")
class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    var id: Long? = null
    var username: String? = null
    var password: String? = null
    var phone: String? = null
    var email: String? = null

    @ManyToMany(cascade = [CascadeType.REFRESH], fetch = FetchType.EAGER)
    @JoinTable(
        name = "user_mtm_role",
        joinColumns = [JoinColumn(name = "user_id")],
        inverseJoinColumns = [JoinColumn(name = "role_id")]
    )
    var roleList: MutableList<Role>? = null
}
