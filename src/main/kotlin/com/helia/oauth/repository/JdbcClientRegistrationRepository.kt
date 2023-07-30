package com.helia.oauth.repository

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.jdbc.core.*
import org.springframework.security.jackson2.SecurityJackson2Modules
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.core.AuthenticationMethod
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.util.Assert
import org.springframework.util.StringUtils
import java.sql.ResultSet
import java.sql.SQLException
import java.util.*
import java.util.function.Function

/**
 * OAuth2 Client Persistence Extension
 *
 */
internal class JdbcClientRegistrationRepository(jdbcOperations: JdbcOperations) : ClientRegistrationRepository,
    Iterable<ClientRegistration?> {
    private val jdbcOperations: JdbcOperations
    private val clientRegistrationRowMapper: RowMapper<ClientRegistration>
    private val clientRegistrationListParametersMapper: Function<ClientRegistration, List<SqlParameterValue>>

    init {
        Assert.notNull(jdbcOperations, "JdbcOperations can not be null")
        this.jdbcOperations = jdbcOperations
        clientRegistrationRowMapper = ClientRegistrationRowMapper()
        clientRegistrationListParametersMapper = ClientRegistrationParametersMapper()
    }

    override fun findByRegistrationId(registrationId: String): ClientRegistration? {
        Assert.hasText(registrationId, "registrationId cannot be empty")
        return findBy("registration_id = ?", registrationId)
    }

    private fun findBy(filter: String, vararg args: Any): ClientRegistration? {
        val result = jdbcOperations.query(LOAD_CLIENT_REGISTERED_QUERY_SQL + filter, clientRegistrationRowMapper, *args)
        return if (!result.isEmpty()) result[0] else null
    }

    fun save(clientRegistration: ClientRegistration) {
        Assert.notNull(clientRegistration, "clientRegistration cannot be null")
        val existingClientRegistration = findByRegistrationId(clientRegistration.registrationId)
        if (existingClientRegistration != null) {
            updateRegisteredClient(clientRegistration)
        } else {
            insertClientRegistration(clientRegistration)
        }
    }

    private fun updateRegisteredClient(clientRegistration: ClientRegistration) {
        val parameterValues = clientRegistrationListParametersMapper.apply(clientRegistration)
        val statementSetter: PreparedStatementSetter = ArgumentPreparedStatementSetter(parameterValues.toTypedArray())
        jdbcOperations.update(UPDATE_CLIENT_REGISTERED_SQL, statementSetter)
    }

    private fun insertClientRegistration(clientRegistration: ClientRegistration) {
        val parameterValues = clientRegistrationListParametersMapper.apply(clientRegistration)
        val statementSetter: PreparedStatementSetter = ArgumentPreparedStatementSetter(parameterValues.toTypedArray())
        jdbcOperations.update(INSERT_CLIENT_REGISTERED_SQL, statementSetter)
    }

    fun findAny(): List<ClientRegistration> {
        val result = jdbcOperations.query(LOAD_CLIENT_REGISTERED_SQL, clientRegistrationRowMapper)
        return if (result.isEmpty()) emptyList() else result
    }

    override fun iterator(): Iterator<ClientRegistration> {
        return findAny().iterator()
    }

    class ClientRegistrationRowMapper : RowMapper<ClientRegistration> {
        private val objectMapper = ObjectMapper()

        init {
            val classLoader = JdbcClientRegistrationRepository::class.java.classLoader
            val securityModules = SecurityJackson2Modules.getModules(classLoader)
            objectMapper.registerModules(securityModules)
        }

        @Throws(SQLException::class)
        override fun mapRow(rs: ResultSet, rowNum: Int): ClientRegistration {
            val scopes = StringUtils.commaDelimitedListToSet(rs.getString("scopes"))
            val builder = ClientRegistration.withRegistrationId(rs.getString("registration_id"))
                .clientId(rs.getString("client_id"))
                .clientSecret(rs.getString("client_secret"))
                .clientAuthenticationMethod(resolveClientAuthenticationMethod(rs.getString("client_authentication_method")))
                .authorizationGrantType(resolveAuthorizationGrantType(rs.getString("authorization_grant_type")))
                .clientName(rs.getString("client_name"))
                .redirectUri(rs.getString("redirect_uri"))
                .scope(scopes)
                .authorizationUri(rs.getString("authorization_uri"))
                .tokenUri(rs.getString("token_uri"))
                .jwkSetUri(rs.getString("jwk_set_uri"))
                .issuerUri(rs.getString("issuer_uri"))
                .userInfoUri(rs.getString("user_info_uri"))
                .userInfoAuthenticationMethod(resolveUserInfoAuthenticationMethod(rs.getString("user_info_authentication_method")))
                .userNameAttributeName(rs.getString("user_name_attribute_name"))
            val configurationMetadata = parseMap(rs.getString("configuration_metadata"))
            builder.providerConfigurationMetadata(configurationMetadata)
            return builder.build()
        }

        private fun parseMap(data: String): Map<String, Any> {
            return try {
                objectMapper.readValue(data, object : TypeReference<Map<String, Any>>() {})
            } catch (var3: Exception) {
                throw IllegalArgumentException(var3.message, var3)
            }
        }

        companion object {
            private fun resolveAuthorizationGrantType(authorizationGrantType: String): AuthorizationGrantType {
                return if (AuthorizationGrantType.AUTHORIZATION_CODE.value == authorizationGrantType) {
                    AuthorizationGrantType.AUTHORIZATION_CODE
                } else if (AuthorizationGrantType.CLIENT_CREDENTIALS.value == authorizationGrantType) {
                    AuthorizationGrantType.CLIENT_CREDENTIALS
                } else {
                    if (AuthorizationGrantType.REFRESH_TOKEN.value == authorizationGrantType) AuthorizationGrantType.REFRESH_TOKEN else AuthorizationGrantType(
                        authorizationGrantType
                    )
                }
            }

            private fun resolveClientAuthenticationMethod(clientAuthenticationMethod: String): ClientAuthenticationMethod {
                return if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.value == clientAuthenticationMethod) {
                    ClientAuthenticationMethod.CLIENT_SECRET_BASIC
                } else if (ClientAuthenticationMethod.CLIENT_SECRET_POST.value == clientAuthenticationMethod) {
                    ClientAuthenticationMethod.CLIENT_SECRET_POST
                } else {
                    if (ClientAuthenticationMethod.NONE.value == clientAuthenticationMethod) ClientAuthenticationMethod.NONE else ClientAuthenticationMethod(
                        clientAuthenticationMethod
                    )
                }
            }

            private fun resolveUserInfoAuthenticationMethod(userInfoAuthenticationMethod: String): AuthenticationMethod {
                return if (AuthenticationMethod.FORM.value == userInfoAuthenticationMethod) {
                    AuthenticationMethod.FORM
                } else if (AuthenticationMethod.HEADER.value == userInfoAuthenticationMethod) {
                    AuthenticationMethod.HEADER
                } else {
                    if (AuthenticationMethod.QUERY.value == userInfoAuthenticationMethod) AuthenticationMethod.QUERY else AuthenticationMethod(
                        userInfoAuthenticationMethod
                    )
                }
            }
        }
    }

    class ClientRegistrationParametersMapper : Function<ClientRegistration, List<SqlParameterValue>> {
        private val objectMapper = ObjectMapper()

        init {
            val classLoader = JdbcClientRegistrationRepository::class.java.classLoader
            val securityModules = SecurityJackson2Modules.getModules(classLoader)
            objectMapper.registerModules(securityModules)
        }

        override fun apply(clientRegistration: ClientRegistration): List<SqlParameterValue> {
            return Arrays.asList(
                SqlParameterValue(12, clientRegistration.registrationId),
                SqlParameterValue(12, clientRegistration.clientId),
                SqlParameterValue(12, clientRegistration.clientSecret),
                SqlParameterValue(12, clientRegistration.clientAuthenticationMethod.value),
                SqlParameterValue(12, clientRegistration.authorizationGrantType.value),
                SqlParameterValue(12, clientRegistration.clientName),
                SqlParameterValue(12, clientRegistration.redirectUri),
                SqlParameterValue(12, StringUtils.collectionToCommaDelimitedString(clientRegistration.scopes)),
                SqlParameterValue(12, clientRegistration.providerDetails.authorizationUri),
                SqlParameterValue(12, clientRegistration.providerDetails.tokenUri),
                SqlParameterValue(12, clientRegistration.providerDetails.jwkSetUri),
                SqlParameterValue(12, clientRegistration.providerDetails.issuerUri),
                SqlParameterValue(12, clientRegistration.providerDetails.userInfoEndpoint.uri),
                SqlParameterValue(12, clientRegistration.providerDetails.userInfoEndpoint.authenticationMethod.value),
                SqlParameterValue(12, clientRegistration.providerDetails.userInfoEndpoint.userNameAttributeName),
                SqlParameterValue(12, writeMap(clientRegistration.providerDetails.configurationMetadata))
            )
        }

        private fun writeMap(data: Map<String, Any>): String {
            return try {
                objectMapper.writeValueAsString(data)
            } catch (var3: Exception) {
                throw IllegalArgumentException(var3.message, var3)
            }
        }
    }

    companion object {
        private const val COLUMN_NAMES =
            "registration_id,client_id,client_secret,client_authentication_method,authorization_grant_type,client_name,redirect_uri,scopes,authorization_uri,token_uri,jwk_set_uri,issuer_uri,user_info_uri,user_info_authentication_method,user_name_attribute_name,configuration_metadata"
        private const val TABLE_NAME = "oauth2_client_registered"
        private const val LOAD_CLIENT_REGISTERED_SQL = "SELECT " + COLUMN_NAMES + " FROM " + TABLE_NAME
        private const val LOAD_CLIENT_REGISTERED_QUERY_SQL = LOAD_CLIENT_REGISTERED_SQL + " WHERE "
        private const val INSERT_CLIENT_REGISTERED_SQL =
            "INSERT INTO " + TABLE_NAME + "(" + COLUMN_NAMES + ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
        private const val UPDATE_CLIENT_REGISTERED_SQL =
            "UPDATE " + TABLE_NAME + " SET client_id = ?,client_secret = ?,client_authentication_method = ?,authorization_grant_type = ?,client_name = ?,redirect_uri = ?,scopes = ?,authorization_uri = ?,token_uri = ?,jwk_set_uri = ?,issuer_uri = ?,user_info_uri = ?,user_info_authentication_method = ?,user_name_attribute_name = ?,configuration_metadata = ? WHERE registration_id = ?"
    }
}
