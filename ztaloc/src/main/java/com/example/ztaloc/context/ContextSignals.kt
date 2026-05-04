package com.example.ztaloc.context

data class ContextSignals(
    val trustedNetwork: Boolean,
    val requestHour: Int,
    val withinExpectedHours: Boolean,
    val requestFresh: Boolean,
    val notes: List<String>
)