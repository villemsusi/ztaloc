package com.example.ztaloc.data

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
