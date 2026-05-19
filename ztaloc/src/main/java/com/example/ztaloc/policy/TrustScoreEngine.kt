package com.example.ztaloc.policy

class TrustScoreEngine(
    private val registeredDevicePoints: Double,
    private val deviceIntegrityPoints: Double,
    private val osVersionPoints: Double,
    private val hardwareBackedKeysPoints: Double,
    private val secureLockPoints: Double,
    private val applicationChecksumPoints: Double,
    private val permissionPolicyPoints: Double,
    private val trustedNetworkPoints: Double,
    private val expectedHoursPoints: Double,
    private val requestFreshnessPoints: Double,
    private val expectedCountryPoints: Double,
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
        if (inputs.devicePosture.permissionPolicyMatches) device += permissionPolicyPoints

        var context = 0.0
        if (inputs.contextSignals.trustedNetwork) context += trustedNetworkPoints
        if (inputs.contextSignals.withinExpectedHours) context += expectedHoursPoints
        if (inputs.contextSignals.requestFresh) context += requestFreshnessPoints
        if (inputs.contextSignals.countryAllowed) context += expectedCountryPoints

        var behavior = 0.0
        if (inputs.behaviorSignals.normalRequestRate) behavior += normalRequestRatePoints
        if (!inputs.behaviorSignals.repeatedFailures) behavior += noRepeatedFailuresPoints
        if (!inputs.behaviorSignals.impossibleMovementSuspected) behavior += plausibleMovementPoints

        val trustRecency = (inputs.trustRecencySignals.rawScore.coerceIn(0, 10) / 10.0) * trustRecencyPoints
        behavior += trustRecency

        val total = (device + context + behavior).coerceIn(0.0, 100.0)
        return TrustScoreResult(
            total = total.toInt(),
            identityAuthenticated = inputs.identityAuthenticated,
            multiFactorSatisfied = inputs.multiFactorSatisfied,
            registeredDevice = inputs.devicePosture.isRegistered,
            rootOrJailbreakSuspected = inputs.devicePosture.rootOrJailbreakSuspected,
            applicationChecksumMatches = inputs.devicePosture.applicationChecksumMatches,
            secureLockEnabled = inputs.devicePosture.secureLockEnabled,
            hardwareBackedKeysAvailable = inputs.devicePosture.hardwareBackedKeysAvailable,
            requestFresh = inputs.contextSignals.requestFresh,
            repeatedFailures = inputs.behaviorSignals.repeatedFailures,
            impossibleMovementSuspected = inputs.behaviorSignals.impossibleMovementSuspected,
            device = device,
            context = context,
            behavior = behavior,
            trustRecency = trustRecency,
            deviceMax = registeredDevicePoints + deviceIntegrityPoints + osVersionPoints + hardwareBackedKeysPoints + secureLockPoints + applicationChecksumPoints + permissionPolicyPoints,
            contextMax = trustedNetworkPoints + expectedHoursPoints + requestFreshnessPoints + expectedCountryPoints,
            behaviorMax = normalRequestRatePoints + noRepeatedFailuresPoints + plausibleMovementPoints + trustRecencyPoints,
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
    val secureLockEnabled: Boolean,
    val hardwareBackedKeysAvailable: Boolean,
    val requestFresh: Boolean,
    val repeatedFailures: Boolean,
    val impossibleMovementSuspected: Boolean,
    val device: Double,
    val context: Double,
    val behavior: Double,
    val trustRecency: Double,
    val deviceMax: Double,
    val contextMax: Double,
    val behaviorMax: Double,
    val trustRecencyMax: Double
)
