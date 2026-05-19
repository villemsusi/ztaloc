package com.example.ztaloc.context

import kotlinx.serialization.Serializable

@Serializable
data class ContextSignals(
    val trustedNetwork: Boolean,
    val requestHour: Int,
    val withinExpectedHours: Boolean,
    val requestFresh: Boolean,
    val countryAllowed: Boolean = true,
    val countryIsoCode: String? = null,
    val notes: List<String>
)
