package com.example.ztaloc.core

import okhttp3.HttpUrl

data class ZtaConfig(
    val relayBaseUrl: HttpUrl? = null,
    val appPackageName: String? = null,
    val appVersion: String? = null,
    val applicationChecksumSha256: String? = null,
    val trustedWifiSsids: Set<String> = emptySet(),
    val knownHoursStart: Int = 6,
    val knownHoursEnd: Int = 23,
    val enablePlayIntegrityChecks: Boolean = true,
    val preciseThreshold: Int = 90,
    val approximateThreshold: Int = 80,
    val semanticThreshold: Int = 70,
    val minimumCategoryScore: Int = 10,
    val registeredDevicePoints: Double? = null,
    val deviceIntegrityPoints: Double? = null,
    val osVersionPoints: Double? = null,
    val hardwareBackedKeysPoints: Double? = null,
    val secureLockPoints: Double? = null,
    val applicationChecksumPoints: Double? = null,
    val trustedNetworkPoints: Double? = null,
    val expectedHoursPoints: Double? = null,
    val requestFreshnessPoints: Double? = null,
    val normalRequestRatePoints: Double? = null,
    val noRepeatedFailuresPoints: Double? = null,
    val plausibleMovementPoints: Double? = null,
    val trustRecencyPoints: Double? = null,
    val requestFreshnessMs: Long = 60_000L,
    val requestTimeoutMs: Long = 10_000L,
    val approximateMaxOffsetKm: Double = 20.0,
    val semanticLabelRadiusMeters: Double = 100.0
) {
    init {
        require(knownHoursStart in 0..23) { "knownHoursStart must be between 0 and 23" }
        require(knownHoursEnd in 0..23) { "knownHoursEnd must be between 0 and 23" }
        require(preciseThreshold in 0..100) { "preciseThreshold must be between 0 and 100" }
        require(approximateThreshold in 0..100) { "approximateThreshold must be between 0 and 100" }
        require(semanticThreshold in 0..100) { "semanticThreshold must be between 0 and 100" }
        require(preciseThreshold >= approximateThreshold) {
            "preciseThreshold must be greater than or equal to approximateThreshold"
        }
        require(approximateThreshold >= semanticThreshold) {
            "approximateThreshold must be greater than or equal to semanticThreshold"
        }
        require(minimumCategoryScore in 0..50) { "minimumCategoryScore must be between 0 and 50" }
        resolvedTrustSignalPoints()
        require(requestFreshnessMs > 0) { "requestFreshnessMs must be greater than 0" }
        require(requestTimeoutMs > 0) { "requestTimeoutMs must be greater than 0" }
        require(approximateMaxOffsetKm > 0.0) { "approximateMaxOffsetKm must be greater than 0" }
        require(semanticLabelRadiusMeters > 0.0) { "semanticLabelRadiusMeters must be greater than 0" }
    }

    fun resolvedTrustSignalPoints(): TrustSignalPoints {
        val configured = listOf(
            registeredDevicePoints,
            deviceIntegrityPoints,
            osVersionPoints,
            hardwareBackedKeysPoints,
            secureLockPoints,
            applicationChecksumPoints,
            trustedNetworkPoints,
            expectedHoursPoints,
            requestFreshnessPoints,
            normalRequestRatePoints,
            noRepeatedFailuresPoints,
            plausibleMovementPoints,
            trustRecencyPoints
        )

        require(configured.filterNotNull().all { it >= 0.0 }) {
            "Trust signal point values must not be negative"
        }

        val configuredTotal = configured.filterNotNull().sum()
        val adaptiveCount = configured.count { it == null }
        require(configuredTotal <= 100.0 + FLOAT_TOLERANCE) {
            "Configured trust signal point values must not exceed 100"
        }

        val adaptiveValue = if (adaptiveCount == 0) {
            require(kotlin.math.abs(configuredTotal - 100.0) <= FLOAT_TOLERANCE) {
                "Configured trust signal point values must add up to 100"
            }
            0.0
        } else {
            (100.0 - configuredTotal) / adaptiveCount
        }

        fun resolve(value: Double?): Double = value ?: adaptiveValue

        return TrustSignalPoints(
            registeredDevice = resolve(registeredDevicePoints),
            deviceIntegrity = resolve(deviceIntegrityPoints),
            osVersion = resolve(osVersionPoints),
            hardwareBackedKeys = resolve(hardwareBackedKeysPoints),
            secureLock = resolve(secureLockPoints),
            applicationChecksum = resolve(applicationChecksumPoints),
            trustedNetwork = resolve(trustedNetworkPoints),
            expectedHours = resolve(expectedHoursPoints),
            requestFreshness = resolve(requestFreshnessPoints),
            normalRequestRate = resolve(normalRequestRatePoints),
            noRepeatedFailures = resolve(noRepeatedFailuresPoints),
            plausibleMovement = resolve(plausibleMovementPoints),
            trustRecency = resolve(trustRecencyPoints)
        )
    }

    private companion object {
        private const val FLOAT_TOLERANCE = 0.0001
    }
}

data class TrustSignalPoints(
    val registeredDevice: Double,
    val deviceIntegrity: Double,
    val osVersion: Double,
    val hardwareBackedKeys: Double,
    val secureLock: Double,
    val applicationChecksum: Double,
    val trustedNetwork: Double,
    val expectedHours: Double,
    val requestFreshness: Double,
    val normalRequestRate: Double,
    val noRepeatedFailures: Double,
    val plausibleMovement: Double,
    val trustRecency: Double
)
