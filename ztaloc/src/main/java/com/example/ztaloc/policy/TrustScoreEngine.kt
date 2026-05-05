package com.example.ztaloc.policy

class TrustScoreEngine {
    fun calculate(inputs: TrustInputs): TrustScoreResult {
        var device = 0
        if (inputs.devicePosture.isRegistered) device += 15
        if (inputs.devicePosture.passesIntegrity && !inputs.devicePosture.rootOrJailbreakSuspected) device += 15
        if (inputs.devicePosture.osVersionRecentEnough) device += 7
        if (inputs.devicePosture.hardwareBackedKeysAvailable) device += 7
        if (inputs.devicePosture.secureLockEnabled) device += 6

        var context = 0
        if (inputs.contextSignals.trustedNetwork) context += 10
        if (inputs.contextSignals.withinExpectedHours) context += 10
        if (inputs.contextSignals.requestFresh) context += 10

        var behavior = 20
        if (!inputs.behaviorSignals.normalRequestRate) behavior -= 10
        if (inputs.behaviorSignals.repeatedFailures) behavior -= 5
        if (inputs.behaviorSignals.impossibleMovementSuspected) behavior -= 10
        if (behavior < 0) behavior = 0

        val total = (device + context + behavior).coerceIn(0, 100)
        return TrustScoreResult(
            total = total,
            identityAuthenticated = inputs.identityAuthenticated,
            multiFactorSatisfied = inputs.multiFactorSatisfied,
            device = device.coerceIn(0, 50),
            context = context.coerceIn(0, 30),
            behavior = behavior.coerceIn(0, 20)
        )
    }
}

data class TrustScoreResult(
    val total: Int,
    val identityAuthenticated: Boolean,
    val multiFactorSatisfied: Boolean,
    val device: Int,
    val context: Int,
    val behavior: Int
)
