package com.example.ztaloc.policy

class TrustScoreEngine(
    private val registeredDevicePoints: Double,
    private val deviceIntegrityPoints: Double,
    private val osVersionPoints: Double,
    private val hardwareBackedKeysPoints: Double,
    private val secureLockPoints: Double,
    private val applicationChecksumPoints: Double,
    private val trustedNetworkPoints: Double,
    private val expectedHoursPoints: Double,
    private val requestFreshnessPoints: Double,
    private val normalRequestRatePoints: Double,
    private val noRepeatedFailuresPoints: Double,
    private val plausibleMovementPoints: Double,
    private val trustRecencyPoints: Double
) {
    fun calculate(inputs: TrustInputs): TrustScoreResult {
        var device = 0.0
        if (inputs.devicePosture.isRegistered) device += registeredDevicePoints
        if (inputs.devicePosture.passesIntegrity && !inputs.devicePosture.rootOrJailbreakSuspected) device += deviceIntegrityPoints
        if (inputs.devicePosture.osVersionRecentEnough) device += osVersionPoints
        if (inputs.devicePosture.hardwareBackedKeysAvailable) device += hardwareBackedKeysPoints
        if (inputs.devicePosture.secureLockEnabled) device += secureLockPoints
        if (inputs.devicePosture.applicationChecksumMatches) device += applicationChecksumPoints

        var context = 0.0
        if (inputs.contextSignals.trustedNetwork) context += trustedNetworkPoints
        if (inputs.contextSignals.withinExpectedHours) context += expectedHoursPoints
        if (inputs.contextSignals.requestFresh) context += requestFreshnessPoints

        var behavior = 0.0
        if (inputs.behaviorSignals.normalRequestRate) behavior += normalRequestRatePoints
        if (!inputs.behaviorSignals.repeatedFailures) behavior += noRepeatedFailuresPoints
        if (!inputs.behaviorSignals.impossibleMovementSuspected) behavior += plausibleMovementPoints

        val trustRecency = (inputs.trustRecencySignals.rawScore.coerceIn(0, 10) / 10.0) * trustRecencyPoints

        val total = (device + context + behavior + trustRecency).coerceIn(0.0, 100.0)
        return TrustScoreResult(
            total = total.toInt(),
            identityAuthenticated = inputs.identityAuthenticated,
            multiFactorSatisfied = inputs.multiFactorSatisfied,
            registeredDevice = inputs.devicePosture.isRegistered,
            rootOrJailbreakSuspected = inputs.devicePosture.rootOrJailbreakSuspected,
            applicationChecksumMatches = inputs.devicePosture.applicationChecksumMatches,
            device = device,
            context = context,
            behavior = behavior,
            trustRecency = trustRecency,
            deviceMax = registeredDevicePoints + deviceIntegrityPoints + osVersionPoints + hardwareBackedKeysPoints + secureLockPoints + applicationChecksumPoints,
            contextMax = trustedNetworkPoints + expectedHoursPoints + requestFreshnessPoints,
            behaviorMax = normalRequestRatePoints + noRepeatedFailuresPoints + plausibleMovementPoints,
            trustRecencyMax = trustRecencyPoints
        )
    }
}

data class TrustScoreResult(
    val total: Int,
    val identityAuthenticated: Boolean,
    val multiFactorSatisfied: Boolean,
    val registeredDevice: Boolean,
    val rootOrJailbreakSuspected: Boolean,
    val applicationChecksumMatches: Boolean,
    val device: Double,
    val context: Double,
    val behavior: Double,
    val trustRecency: Double,
    val deviceMax: Double,
    val contextMax: Double,
    val behaviorMax: Double,
    val trustRecencyMax: Double
)
