package com.example.ztaloc.location

import com.example.ztaloc.api.LocationExposure
import com.example.ztaloc.api.LocationPayload
import kotlin.math.round

class LocationTransformer {
    fun transform(location: PreciseLocation, exposure: LocationExposure): LocationPayload {
        return when (exposure) {
            LocationExposure.PRECISE -> LocationPayload(
                latitude = location.latitude,
                longitude = location.longitude,
                timestampEpochMs = location.timestampEpochMs
            )
            LocationExposure.APPROXIMATE -> LocationPayload(
                latitude = round(location.latitude * 100.0) / 100.0,
                longitude = round(location.longitude * 100.0) / 100.0,
                radiusMeters = 1000.0,
                timestampEpochMs = location.timestampEpochMs
            )
            LocationExposure.SEMANTIC -> LocationPayload(
                semanticLabel = inferSemanticLabel(location),
                timestampEpochMs = location.timestampEpochMs
            )
            LocationExposure.NONE -> LocationPayload(timestampEpochMs = location.timestampEpochMs)
        }
    }

    private fun inferSemanticLabel(location: PreciseLocation): String = "known_area"
}