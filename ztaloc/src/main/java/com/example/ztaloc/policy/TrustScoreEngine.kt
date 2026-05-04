package com.example.ztaloc.policy

class TrustScoreEngine {
    fun calculate(inputs: TrustInputs): TrustScoreResult {
        var identity = 0
        if (inputs.identityAuthenticated) identity += 15
        if (inputs.multiFactorSatisfied) identity += 15

        var device = 0
        if (inputs.devicePosture.isRegistered) device += 10
        if (inputs.devicePosture.passesIntegrity && !inputs.devicePosture.rootOrJailbreakSuspected) device += 10
        if (inputs.devicePosture.osVersionRecentEnough) device += 5
        if (inputs.devicePosture.hardwareBackedKeysAvailable && inputs.devicePosture.secureLockEnabled) device += 5

        var context = 0
        if (inputs.contextSignals.trustedNetwork) context += 5
        if (inputs.contextSignals.withinExpectedHours) context += 10
        if (inputs.contextSignals.requestFresh) context += 5

        var behavior = 20
        if (!inputs.behaviorSignals.normalRequestRate) behavior -= 10
        if (inputs.behaviorSignals.repeatedFailures) behavior -= 5
        if (inputs.behaviorSignals.impossibleMovementSuspected) behavior -= 10
        if (behavior < 0) behavior = 0

        val total = (identity + device + context + behavior).coerceIn(0, 100)
        return TrustScoreResult(total, identity, device, context, behavior)
    }
}

data class TrustScoreResult(
    val total: Int,
    val identity: Int,
    val device: Int,
    val context: Int,
    val behavior: Int
)