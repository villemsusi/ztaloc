package com.example.ztaloc.behavior

import kotlinx.serialization.Serializable

@Serializable
data class BehaviorSignals(
    val normalRequestRate: Boolean,
    val repeatedFailures: Boolean,
    val impossibleMovementSuspected: Boolean,
    val notes: List<String>
)
