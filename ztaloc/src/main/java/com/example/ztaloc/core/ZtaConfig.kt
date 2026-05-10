package com.example.ztaloc.core

import okhttp3.HttpUrl

data class ZtaConfig(
    val relayBaseUrl: HttpUrl? = null,
    val appPackageName: String? = null,
    val appVersion: String? = null,
    val trustedWifiSsids: Set<String> = emptySet(),
    val knownHoursStart: Int = 6,
    val knownHoursEnd: Int = 23,
    val enablePlayIntegrityChecks: Boolean = true,
    val preciseThreshold: Int = 81,
    val approximateThreshold: Int = 70,
    val semanticThreshold: Int = 60,
    val minimumCategoryScore: Int = 10,
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
        require(requestFreshnessMs > 0) { "requestFreshnessMs must be greater than 0" }
        require(requestTimeoutMs > 0) { "requestTimeoutMs must be greater than 0" }
        require(approximateMaxOffsetKm > 0.0) { "approximateMaxOffsetKm must be greater than 0" }
        require(semanticLabelRadiusMeters > 0.0) { "semanticLabelRadiusMeters must be greater than 0" }
    }
}
