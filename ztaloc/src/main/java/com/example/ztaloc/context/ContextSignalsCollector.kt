package com.example.ztaloc.context

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import java.time.Instant
import java.time.ZoneId

class ContextSignalsCollector(
    private val context: Context,
    private val knownHoursStart: Int = 6,
    private val knownHoursEnd: Int = 23
) {
    fun collect(requestEpochMs: Long): ContextSignals {
        val notes = mutableListOf<String>()
        val nowHour = Instant.ofEpochMilli(System.currentTimeMillis()).atZone(ZoneId.systemDefault()).hour
        val withinHours = nowHour in knownHoursStart..knownHoursEnd
        if (!withinHours) notes += "Request outside expected hours"
        val freshness = (System.currentTimeMillis() - requestEpochMs) <= 60_000L
        if (!freshness) notes += "Request too old"
        val trustedNetwork = isTrustedNetwork()
        if (!trustedNetwork) notes += "Untrusted or unknown network"
        return ContextSignals(trustedNetwork, nowHour, withinHours, freshness, notes)
    }

    private fun isTrustedNetwork(): Boolean {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val network = cm.activeNetwork ?: return false
        val caps = cm.getNetworkCapabilities(network) ?: return false
        return caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) || caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
    }
}