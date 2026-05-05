package com.example.ztaloc.behavior

class BehaviorMonitor {
    fun collect(recentFailures: Int = 0, recentBurstRequests: Int = 0, impossibleMovement: Boolean = false): BehaviorSignals {
        val notes = mutableListOf<String>()
        val normalRate = recentBurstRequests < 5
        if (!normalRate) notes += "Burst request pattern detected"
        val failures = recentFailures >= 3
        if (failures) notes += "Repeated prior failures"
        if (impossibleMovement) notes += "Implausible movement pattern detected"
        return BehaviorSignals(normalRate, failures, impossibleMovement, notes)
    }
}