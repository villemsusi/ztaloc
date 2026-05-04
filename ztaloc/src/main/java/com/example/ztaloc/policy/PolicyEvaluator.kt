package com.example.ztaloc.policy

import com.example.ztaloc.api.AccessDecision
import com.example.ztaloc.api.LocationExposure
import com.example.ztaloc.core.ZtaConfig

class PolicyEvaluator(private val config: ZtaConfig) {
    fun evaluate(score: Int): PolicyResult {
        return when {
            score >= config.preciseThreshold -> PolicyResult(AccessDecision.ALLOW_PRECISE, LocationExposure.PRECISE, "High trust request")
            score >= config.approximateThreshold -> PolicyResult(AccessDecision.ALLOW_APPROXIMATE, LocationExposure.APPROXIMATE, "Moderate trust request")
            score >= config.semanticThreshold -> PolicyResult(AccessDecision.ALLOW_SEMANTIC, LocationExposure.SEMANTIC, "Low trust request")
            score >= 20 -> PolicyResult(AccessDecision.REQUIRE_STEP_UP, LocationExposure.NONE, "Additional verification required")
            else -> PolicyResult(AccessDecision.DENY, LocationExposure.NONE, "Trust score below minimum threshold")
        }
    }
}

data class PolicyResult(
    val decision: AccessDecision,
    val exposure: LocationExposure,
    val rationale: String
)