package com.example.ztaloc.api

import kotlinx.serialization.Serializable

@Serializable
data class SetupResult(
    val userId: String,
    val deviceId: String,
    val alreadyInitialized: Boolean,
    val message: String
)

@Serializable
data class DeviceRegistrationInfo(
    val userId: String,
    val displayName: String?,
    val deviceId: String,
    val signingPublicKeyB64: String,
    val encryptionPublicKeyB64: String,
    val registeredAtEpochMs: Long
)

@Serializable
data class PairedDevice(
    val userId: String,
    val displayName: String?,
    val deviceId: String,
    val signingPublicKeyB64: String,
    val encryptionPublicKeyB64: String,
    val pairedAtEpochMs: Long
)

@Serializable
data class SemanticLocationLabel(
    val label: String,
    val latitude: Double,
    val longitude: Double,
    val radiusMeters: Double = 100.0
)

@Serializable
data class OutgoingRequest(
    val sessionId: String,
    val targetUserId: String,
    val targetDeviceId: String,
    val payload: String
)

@Serializable
data class OutgoingResponse(
    val sessionId: String,
    val requesterUserId: String,
    val requesterDeviceId: String,
    val decision: AccessDecision,
    val exposure: LocationExposure,
    val trustScore: Int,
    val reason: String,
    val payload: String
)

@Serializable
data class LocationAccessResult(
    val sessionId: String,
    val decision: AccessDecision,
    val trustScore: Int,
    val exposure: LocationExposure,
    val locationPayload: LocationPayload?,
    val reason: String
)

data class LocalAuthenticationResult(
    val authenticated: Boolean,
    val multiFactorSatisfied: Boolean,
    val reason: String
)

@Serializable
enum class AccessDecision {
    ALLOW_PRECISE,
    ALLOW_APPROXIMATE,
    ALLOW_SEMANTIC,
    REQUIRE_STEP_UP,
    DENY
}
@Serializable
enum class LocationExposure {
    PRECISE,
    APPROXIMATE,
    SEMANTIC,
    NONE
}

@Serializable
data class LocationPayload(
    val latitude: Double? = null,
    val longitude: Double? = null,
    val radiusMeters: Double? = null,
    val semanticLabel: String? = null,
    val timestampEpochMs: Long
)
