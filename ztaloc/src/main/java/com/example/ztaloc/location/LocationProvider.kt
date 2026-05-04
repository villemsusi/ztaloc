package com.example.ztaloc.location

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import androidx.core.content.ContextCompat
import com.google.android.gms.location.FusedLocationProviderClient
import com.google.android.gms.location.LocationServices
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

class LocationProvider(context: Context) {
    private val fused: FusedLocationProviderClient = LocationServices.getFusedLocationProviderClient(context)
    private val appContext = context.applicationContext

    @SuppressLint("MissingPermission")
    suspend fun getCurrentPreciseLocation(): PreciseLocation? {
        val fine = ContextCompat.checkSelfPermission(appContext, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
        if (!fine) return null
        return suspendCancellableCoroutine { cont ->
            fused.lastLocation
                .addOnSuccessListener { loc ->
                    if (loc == null) cont.resume(null)
                    else cont.resume(PreciseLocation(loc.latitude, loc.longitude, System.currentTimeMillis()))
                }
                .addOnFailureListener { cont.resume(null) }
        }
    }
}

data class PreciseLocation(
    val latitude: Double,
    val longitude: Double,
    val timestampEpochMs: Long
)