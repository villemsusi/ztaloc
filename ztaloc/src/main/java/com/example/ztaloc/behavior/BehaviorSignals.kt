package com.example.ztaloc.behavior

data class BehaviorSignals(
    val normalRequestRate: Boolean,
    val repeatedFailures: Boolean,
    val impossibleMovementSuspected: Boolean,
    val notes: List<String>
)

