package com.example.ztaloc.core

import android.os.SystemClock
import android.util.Log

internal class WorkflowTimer(
    private val name: String
) {
    private val startedAtNanos = SystemClock.elapsedRealtimeNanos()
    private var lastMarkNanos = startedAtNanos
    private val marks = mutableListOf<WorkflowTimingMark>()

    fun mark(label: String) {
        val now = SystemClock.elapsedRealtimeNanos()
        marks += WorkflowTimingMark(
            label = label,
            stepMs = nanosToMillis(now - lastMarkNanos),
            totalMs = nanosToMillis(now - startedAtNanos)
        )
        lastMarkNanos = now
    }

    fun finish(): WorkflowTimingResult {
        val result = WorkflowTimingResult(
            name = name,
            totalMs = nanosToMillis(SystemClock.elapsedRealtimeNanos() - startedAtNanos),
            marks = marks.toList()
        )
        Log.d(TAG, result.toLogString())
        return result
    }

    private fun nanosToMillis(nanos: Long): Double = nanos / 1_000_000.0

    private companion object {
        private const val TAG = "ZtaTiming"
    }
}

data class WorkflowTimingResult(
    val name: String,
    val totalMs: Double,
    val marks: List<WorkflowTimingMark>
) {
    fun toLogString(): String {
        val markText = marks.joinToString(", ") {
            "${it.label}=step:${"%.3f".format(it.stepMs)}ms,total:${"%.3f".format(it.totalMs)}ms"
        }
        return "$name total=${"%.3f".format(totalMs)}ms [$markText]"
    }
}

data class WorkflowTimingMark(
    val label: String,
    val stepMs: Double,
    val totalMs: Double
)

object ZtaTiming {
    @Volatile
    var lastCreateLocationRequest: WorkflowTimingResult? = null
        internal set

    @Volatile
    var lastProcessIncomingRequest: WorkflowTimingResult? = null
        internal set

    @Volatile
    var lastProcessIncomingResponse: WorkflowTimingResult? = null
        internal set
}
