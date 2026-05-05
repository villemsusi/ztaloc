package com.example.ztaloc.core

import okhttp3.HttpUrl

data class ZtaConfig(
    val relayBaseUrl: HttpUrl,
    val appPackageName: String,
    val appVersion: String,
    val trustedWifiSsids: Set<String> = emptySet(),
    val knownHoursStart: Int = 6,
    val knownHoursEnd: Int = 23,
    val enablePlayIntegrityChecks: Boolean = true,
    val preciseThreshold: Int = 80,
    val approximateThreshold: Int = 60,
    val semanticThreshold: Int = 40,
    val requestTimeoutMs: Long = 10_000L
)
