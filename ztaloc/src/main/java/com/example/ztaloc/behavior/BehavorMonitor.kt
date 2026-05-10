package com.example.ztaloc.behavior

import com.example.ztaloc.api.AccessDecision
import com.example.ztaloc.data.SessionRecord
import kotlin.math.atan2
import kotlin.math.cos
import kotlin.math.pow
import kotlin.math.sin
import kotlin.math.sqrt

class BehaviorMonitor {
    fun collect(
        sessions: List<SessionRecord> = emptyList(),
        nowEpochMs: Long = System.currentTimeMillis()
    ): BehaviorSignals {
        val notes = mutableListOf<String>()
        val recentBurstRequests = sessions.count { nowEpochMs - it.issuedAtEpochMs <= BURST_WINDOW_MS }
        val recentFailures = sessions.count {
            nowEpochMs - it.issuedAtEpochMs <= FAILURE_WINDOW_MS &&
                FAILED_DECISIONS.contains(it.lastDecision)
        }
        val impossibleMovement = hasImpossibleMovement(sessions)
        val normalRate = recentBurstRequests < MAX_REQUESTS_IN_BURST_WINDOW
        if (!normalRate) notes += "Burst request pattern detected"
        val failures = recentFailures >= MAX_FAILURES_IN_FAILURE_WINDOW
        if (failures) notes += "Repeated prior failures"
        if (impossibleMovement) notes += "Implausible movement pattern detected"
        return BehaviorSignals(normalRate, failures, impossibleMovement, notes)
    }

    private fun hasImpossibleMovement(sessions: List<SessionRecord>): Boolean {
        val locatedSessions = sessions
            .mapNotNull { session ->
                val latitude = session.locationLatitude ?: return@mapNotNull null
                val longitude = session.locationLongitude ?: return@mapNotNull null
                val timestamp = session.locationTimestampEpochMs ?: return@mapNotNull null
                LocatedSession(latitude, longitude, timestamp)
            }
            .sortedBy { it.timestampEpochMs }

        return locatedSessions.zipWithNext().any { (previous, current) ->
            val seconds = (current.timestampEpochMs - previous.timestampEpochMs) / 1000.0
            if (seconds <= 0.0) {
                false
            } else {
                val metersPerSecond = distanceMeters(previous, current) / seconds
                metersPerSecond > MAX_PLAUSIBLE_METERS_PER_SECOND
            }
        }
    }

    private fun distanceMeters(previous: LocatedSession, current: LocatedSession): Double {
        val dLat = Math.toRadians(current.latitude - previous.latitude)
        val dLon = Math.toRadians(current.longitude - previous.longitude)
        val previousLat = Math.toRadians(previous.latitude)
        val currentLat = Math.toRadians(current.latitude)
        val a = sin(dLat / 2.0).pow(2.0) +
            cos(previousLat) * cos(currentLat) * sin(dLon / 2.0).pow(2.0)
        val c = 2.0 * atan2(sqrt(a), sqrt(1.0 - a))
        return EARTH_RADIUS_METERS * c
    }

    private data class LocatedSession(
        val latitude: Double,
        val longitude: Double,
        val timestampEpochMs: Long
    )

    companion object {
        private const val BURST_WINDOW_MS = 5 * 60_000L
        private const val FAILURE_WINDOW_MS = 60 * 60_000L
        private const val MAX_REQUESTS_IN_BURST_WINDOW = 5
        private const val MAX_FAILURES_IN_FAILURE_WINDOW = 3
        private const val MAX_PLAUSIBLE_METERS_PER_SECOND = 100.0
        private const val EARTH_RADIUS_METERS = 6_371_000.0
        private val FAILED_DECISIONS = setOf(
            AccessDecision.DENY.name,
            AccessDecision.REQUIRE_STEP_UP.name
        )
    }
}
