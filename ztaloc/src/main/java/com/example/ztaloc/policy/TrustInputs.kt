package com.example.ztaloc.policy

import com.example.ztaloc.behavior.BehaviorSignals
import com.example.ztaloc.context.ContextSignals
import com.example.ztaloc.device.DevicePosture


data class TrustInputs(
    val identityAuthenticated: Boolean,
    val multiFactorSatisfied: Boolean,
    val devicePosture: DevicePosture,
    val contextSignals: ContextSignals,
    val behaviorSignals: BehaviorSignals
)
