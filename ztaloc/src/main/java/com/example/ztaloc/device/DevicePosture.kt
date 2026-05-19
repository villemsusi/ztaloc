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
    val permissionPolicyMatches: Boolean,
    val missingRequiredPermissions: List<String>,
    val missingRuntimePermissions: List<String>,
    val extraDeclaredPermissions: List<String>,
    val rootOrJailbreakSuspected: Boolean,
    val playIntegrityChecked: Boolean = false,
    val playIntegrityTokenReceived: Boolean = false,
    val rationale: List<String>
)
