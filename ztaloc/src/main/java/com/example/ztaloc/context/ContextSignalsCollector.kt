package com.example.ztaloc.context

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.location.Geocoder
import android.location.Location
import android.location.LocationManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.telephony.TelephonyManager
import androidx.core.content.ContextCompat
import java.time.Instant
import java.time.ZoneId

class ContextSignalsCollector(
    private val context: Context,
    private val knownHoursStart: Int = 6,
    private val knownHoursEnd: Int = 23,
    private val requestFreshnessMs: Long = 60_000L,
    private val expectedCountryIsoCodes: Set<String> = emptySet(),
    private val trustedWifiSsids: Set<String> = emptySet()
) {
    fun collect(requestEpochMs: Long): ContextSignals {
        val notes = mutableListOf<String>()
        val nowHour = Instant.ofEpochMilli(System.currentTimeMillis()).atZone(ZoneId.systemDefault()).hour
        val withinHours = nowHour in knownHoursStart..knownHoursEnd
        if (!withinHours) notes += "Request outside expected hours"
        val freshness = (System.currentTimeMillis() - requestEpochMs) <= requestFreshnessMs
        if (!freshness) notes += "Request too old"
        val trustedNetwork = isTrustedNetwork()
        if (!trustedNetwork) notes += "Untrusted or unknown network"
        val countryIsoCode = countryFromLastKnownLocation()
        val countryAllowed = expectedCountryIsoCodes.isEmpty() ||
            countryIsoCode?.let { expectedCountryIsoCodes.map(String::uppercase).contains(it) } == true
        if (!countryAllowed) notes += "Request from unusual country"
        return ContextSignals(trustedNetwork, nowHour, withinHours, freshness, countryAllowed, countryIsoCode, notes)
    }

    private fun isTrustedNetwork(): Boolean {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val network = cm.activeNetwork ?: return false
        val caps = cm.getNetworkCapabilities(network) ?: return false
        return when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> isTrustedWifi()
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> isTrustedCellular()
            else -> false
        }
    }

    private fun isTrustedWifi(): Boolean {
        if (trustedWifiSsids.isEmpty()) return false
        val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
            ?: return false
        val ssid = wifiManager.connectionInfo?.ssid
            ?.trim()
            ?.removeSurrounding("\"")
            ?.takeIf { it.isNotBlank() && it != UNKNOWN_SSID }
            ?: return false
        return trustedWifiSsids.any { it.equals(ssid, ignoreCase = true) }
    }

    private fun isTrustedCellular(): Boolean {
        val telephonyManager = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
            ?: return false
        val networkType = runCatching { telephonyManager.dataNetworkType }.getOrDefault(TelephonyManager.NETWORK_TYPE_UNKNOWN)
        return when (networkType) {
            TelephonyManager.NETWORK_TYPE_LTE,
            TelephonyManager.NETWORK_TYPE_IWLAN,
            TelephonyManager.NETWORK_TYPE_NR -> true
            else -> false
        }
    }

    @Suppress("DEPRECATION")
    private fun countryFromLastKnownLocation(): String? {
        val fineGranted = ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
        val coarseGranted = ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED
        if (!fineGranted && !coarseGranted) return null

        val locationManager = context.getSystemService(Context.LOCATION_SERVICE) as? LocationManager
            ?: return null
        val location = runCatching {
            locationManager.getProviders(true)
                .mapNotNull { provider -> runCatching { locationManager.getLastKnownLocation(provider) }.getOrNull() }
                .maxByOrNull(Location::getTime)
        }.getOrNull() ?: return null

        return runCatching {
            Geocoder(context)
                .getFromLocation(location.latitude, location.longitude, 1)
                ?.firstOrNull()
                ?.countryCode
                ?.uppercase()
        }.getOrNull()
    }

    private companion object {
        private const val UNKNOWN_SSID = "<unknown ssid>"
    }
}
