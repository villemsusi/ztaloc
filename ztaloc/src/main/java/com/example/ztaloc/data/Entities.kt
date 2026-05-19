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
    val lastDecision: String,
    val locationLatitude: Double? = null,
    val locationLongitude: Double? = null,
    val locationTimestampEpochMs: Long? = null
)

@Serializable
data class AuditLogEntry(
    val sequence: Long,
    val eventType: String,
    val subjectUserId: String?,
    val subjectDeviceId: String?,
    val sessionId: String?,
    val result: String,
    val issuedAtEpochMs: Long,
    val metadata: Map<String, String> = emptyMap(),
    val previousHashB64: String?,
    val entryHashB64: String,
    val signatureB64: String
)

@Serializable
data class PairedDeviceList(
    val devices: List<PairedDevice>
)

@Serializable
data class AuditLogEntryList(
    val entries: List<AuditLogEntry>
)

@Serializable
data class SemanticLocationLabelList(
    val labels: List<SemanticLocationLabel>
)
