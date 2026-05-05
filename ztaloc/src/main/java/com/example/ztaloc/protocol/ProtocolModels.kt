package com.example.ztaloc.protocol

import com.example.ztaloc.policy.TrustInputs
import kotlinx.serialization.Serializable

@Serializable
data class UnsignedRequestClaims(
    val sessionId: String,
    val requesterUserId: String,
    val requesterDisplayName: String?,
    val requesterDeviceId: String,
    val requesterSigningPublicKeyB64: String,
    val requestEpochMs: Long,
    val requesterTrustInputs: TrustInputs
)

@Serializable
data class RequestClaims(
    val sessionId: String,
    val requesterUserId: String,
    val requesterDisplayName: String?,
    val requesterDeviceId: String,
    val requesterSigningPublicKeyB64: String,
    val requestEpochMs: Long,
    val requesterTrustInputs: TrustInputs,
    val signatureB64: String
)

@Serializable
data class UnsignedResponseClaims(
    val sessionId: String,
    val targetUserId: String,
    val targetDeviceId: String,
    val targetSigningPublicKeyB64: String,
    val trustScore: Int,
    val decision: String,
    val exposure: String,
    val locationJson: String?,
    val reason: String,
    val issuedAtEpochMs: Long
)

@Serializable
data class ResponseClaims(
    val sessionId: String,
    val targetUserId: String,
    val targetDeviceId: String,
    val targetSigningPublicKeyB64: String,
    val trustScore: Int,
    val decision: String,
    val exposure: String,
    val locationJson: String?,
    val reason: String,
    val issuedAtEpochMs: Long,
    val signatureB64: String
)
