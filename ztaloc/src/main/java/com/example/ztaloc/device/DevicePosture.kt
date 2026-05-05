package com.example.ztaloc.device

import kotlinx.serialization.Serializable

@Serializable
data class DevicePosture(
    val isRegistered: Boolean,
    val passesIntegrity: Boolean,
    val osVersionRecentEnough: Boolean,
    val secureLockEnabled: Boolean,
    val hardwareBackedKeysAvailable: Boolean,
    val rootOrJailbreakSuspected: Boolean,
    val rationale: List<String>
)
