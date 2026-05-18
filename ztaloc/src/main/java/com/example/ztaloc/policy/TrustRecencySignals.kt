package com.example.ztaloc.policy

import kotlinx.serialization.Serializable

@Serializable
data class TrustRecencySignals(
    val lastTrustedRequestEpochMs: Long?,
    val monthsSinceLastTrustedRequest: Int?,
    val rawScore: Int,
    val notes: List<String>
)

