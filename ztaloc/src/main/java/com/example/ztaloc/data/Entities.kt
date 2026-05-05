package com.example.ztaloc.data

import com.example.ztaloc.api.PairedDevice
import com.example.ztaloc.api.SemanticLocationLabel
import kotlinx.serialization.Serializable

@Serializable
data class LocalUser(
    val userId: String,
    val displayName: String?,
    val deviceId: String?,
    val registeredAtEpochMs: Long?
)

@Serializable
data class SessionRecord(
    val sessionId: String,
    val requesterUserId: String,
    val targetUserId: String,
    val issuedAtEpochMs: Long,
    val lastTrustScore: Int,
    val lastDecision: String
)

@Serializable
data class PairedDeviceList(
    val devices: List<PairedDevice>
)

@Serializable
data class SemanticLocationLabelList(
    val labels: List<SemanticLocationLabel>
)
