package com.example.ztaloc.network

import kotlinx.serialization.Serializable

@Serializable
data class DeviceRegistrationPayload(
    val userId: String,
    val displayName: String?,
    val deviceId: String,
    val platform: String,
    val appPackageName: String,
    val appVersion: String,
    val publicSigningKeyB64: String,
    val registeredAtEpochMs: Long,
    val signatureB64: String
)

@Serializable
data class DeviceRegistrationResponse(
    val accepted: Boolean,
    val serverAssignedRegistrationId: String? = null,
    val message: String
)

@Serializable
data class RequestEnvelope(
    val sessionId: String,
    val requesterUserId: String,
    val targetUserId: String,
    val requesterDeviceId: String,
    val requestEpochMs: Long,
    val identityAuthenticated: Boolean,
    val multiFactorSatisfied: Boolean,
    val signedPayload: String,
    val signatureB64: String
)

@Serializable
data class ResponseEnvelope(
    val sessionId: String,
    val targetUserId: String,
    val encryptedPayloadJson: String?,

    val plaintextPayloadJson: String? = null,

    val signatureB64: String,
    val issuedAtEpochMs: Long
)
