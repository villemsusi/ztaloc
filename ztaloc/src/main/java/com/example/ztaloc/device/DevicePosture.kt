package com.example.ztaloc.device

import kotlinx.serialization.Serializable

@Serializable
data class DevicePosture(
    val isRegistered: Boolean,
    val passesIntegrity: Boolean,
    val osVersionRecentEnough: Boolean,
    val secureLockEnabled: Boolean,
    val hardwareBackedKeysAvailable: Boolean,
    val applicationChecksumMatches: Boolean,
    val applicationChecksumSha256: String?,
    val expectedApplicationChecksumSha256: String?,
    val rootOrJailbreakSuspected: Boolean,
    val rationale: List<String>
)
