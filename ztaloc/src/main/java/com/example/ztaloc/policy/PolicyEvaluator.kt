package com.example.ztaloc.policy

import com.example.ztaloc.api.AccessDecision
import com.example.ztaloc.api.LocationExposure

class PolicyEvaluator(
    private val preciseThreshold: Int = 81,
    private val approximateThreshold: Int = 70,
    private val semanticThreshold: Int = 60,
    private val minimumCategoryScore: Int = 10
) {
    fun evaluate(score: TrustScoreResult): PolicyResult {
        if (!score.identityAuthenticated) {
            return PolicyResult(AccessDecision.REQUIRE_STEP_UP, LocationExposure.NONE, "User identity must be re-authenticated")
        }
        if (!score.multiFactorSatisfied) {
            return PolicyResult(AccessDecision.REQUIRE_STEP_UP, LocationExposure.NONE, "Additional verification required")
        }
        if (score.device < minimumCategoryScore || score.context < minimumCategoryScore || score.behavior < minimumCategoryScore) {
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
}

data class PolicyResult(
    val decision: AccessDecision,
    val exposure: LocationExposure,
    val rationale: String
)
