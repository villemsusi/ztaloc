package com.example.ztaloc.policy

import com.example.ztaloc.api.AccessDecision
import com.example.ztaloc.api.LocationExposure

class PolicyEvaluator(
    private val preciseThreshold: Int = 90,
    private val approximateThreshold: Int = 80,
    private val semanticThreshold: Int = 70,
    private val minimumCategoryScore: Int = 10
) {
    fun evaluate(score: TrustScoreResult): PolicyResult {
        if (!score.identityAuthenticated) {
            return PolicyResult(AccessDecision.REQUIRE_STEP_UP, LocationExposure.NONE, "User identity must be re-authenticated")
        }
        if (!score.multiFactorSatisfied) {
            return PolicyResult(AccessDecision.REQUIRE_STEP_UP, LocationExposure.NONE, "Additional verification required")
        }
        if (!score.registeredDevice) {
            return PolicyResult(AccessDecision.DENY, LocationExposure.NONE, "Device is not registered")
        }
        if (score.rootOrJailbreakSuspected) {
            return PolicyResult(AccessDecision.DENY, LocationExposure.NONE, "Rooted or compromised OS detected")
        }
        if (!score.applicationChecksumMatches) {
            return PolicyResult(AccessDecision.DENY, LocationExposure.NONE, "Application checksum mismatch")
        }
        if (!score.requestFresh) {
            return PolicyResult(AccessDecision.DENY, LocationExposure.NONE, "Replay or stale request detected")
        }
        if (!score.secureLockEnabled) {
            return PolicyResult(AccessDecision.DENY, LocationExposure.NONE, "Secure lock screen is disabled")
        }
        if (!score.hardwareBackedKeysAvailable) {
            return PolicyResult(AccessDecision.DENY, LocationExposure.NONE, "Hardware-backed keys are unavailable")
        }
        if (score.repeatedFailures) {
            return PolicyResult(AccessDecision.DENY, LocationExposure.NONE, "Repeated failed requests detected")
        }
        if (score.impossibleMovementSuspected) {
            return PolicyResult(AccessDecision.DENY, LocationExposure.NONE, "Impossible travel detected")
        }
        if (
            score.device < requiredCategoryScore(score.deviceMax) ||
            score.context < requiredCategoryScore(score.contextMax) ||
            score.behavior < requiredCategoryScore(score.behaviorMax)
        ) {
            return PolicyResult(AccessDecision.DENY, LocationExposure.NONE, "Minimum trust category score not met")
        }
        return evaluate(score.total)
    }

    fun evaluate(score: Int): PolicyResult {
        return when {
            score >= preciseThreshold -> PolicyResult(AccessDecision.ALLOW_PRECISE, LocationExposure.PRECISE, "High trust request")
            score >= approximateThreshold -> PolicyResult(AccessDecision.ALLOW_APPROXIMATE, LocationExposure.APPROXIMATE, "Moderate trust request")
            score >= semanticThreshold -> PolicyResult(AccessDecision.ALLOW_SEMANTIC, LocationExposure.SEMANTIC, "Low trust request")
            else -> PolicyResult(AccessDecision.DENY, LocationExposure.NONE, "Trust score below minimum threshold")
        }
    }

    private fun requiredCategoryScore(categoryMax: Double): Double {
        return minOf(minimumCategoryScore.toDouble(), categoryMax)
    }
}

data class PolicyResult(
    val decision: AccessDecision,
    val exposure: LocationExposure,
    val rationale: String
)
