package com.example.ztaloc.api

import kotlinx.serialization.Serializable

@Serializable
data class DeviceRegistrationResult(
    val userId: String,
    val deviceId: String,
    val registrationId: String?,
    val registeredAtEpochMs: Long,
    val publicSigningKeyB64: String,
    val message: String
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
