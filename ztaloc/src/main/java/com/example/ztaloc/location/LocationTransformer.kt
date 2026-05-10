package com.example.ztaloc.location

import com.example.ztaloc.api.LocationExposure
import com.example.ztaloc.api.LocationPayload
import com.example.ztaloc.api.SemanticLocationLabel
import java.security.SecureRandom
import kotlin.math.atan2
import kotlin.math.cos
import kotlin.math.pow
import kotlin.math.sin
import kotlin.math.sqrt

class LocationTransformer(
    private val approximateMaxOffsetKm: Double = 20.0
) {
    private val random = SecureRandom()

    fun transform(
        location: PreciseLocation,
        exposure: LocationExposure,
        semanticLabels: List<SemanticLocationLabel> = emptyList()
    ): LocationPayload {
        return when (exposure) {
            LocationExposure.PRECISE -> LocationPayload(
                latitude = location.latitude,
                longitude = location.longitude,
                timestampEpochMs = location.timestampEpochMs
            )
            LocationExposure.APPROXIMATE -> approximate(location)
            LocationExposure.SEMANTIC -> LocationPayload(
                semanticLabel = inferSemanticLabel(location, semanticLabels),
                timestampEpochMs = location.timestampEpochMs
            )
            LocationExposure.NONE -> LocationPayload(timestampEpochMs = location.timestampEpochMs)
        }
    }

    private fun approximate(location: PreciseLocation): LocationPayload {
        val latitudeOffsetKm = randomOffsetKm()
        val longitudeOffsetKm = randomOffsetKm()
        val latitudeOffsetDegrees = latitudeOffsetKm / KM_PER_LATITUDE_DEGREE
        val longitudeDegreesPerKm = KM_PER_LATITUDE_DEGREE * cos(Math.toRadians(location.latitude))
        val longitudeOffsetDegrees = if (longitudeDegreesPerKm == 0.0) {
            0.0
        } else {
            longitudeOffsetKm / longitudeDegreesPerKm
        }

        return LocationPayload(
            latitude = (location.latitude + latitudeOffsetDegrees).coerceIn(-90.0, 90.0),
            longitude = normalizeLongitude(location.longitude + longitudeOffsetDegrees),
            radiusMeters = approximateRadiusMeters(),
            timestampEpochMs = location.timestampEpochMs
        )
    }

    private fun randomOffsetKm(): Double {
        return (random.nextDouble() * 2.0 - 1.0) * approximateMaxOffsetKm
    }

    private fun approximateRadiusMeters(): Double {
        return sqrt(2.0) * approximateMaxOffsetKm * 1000.0
    }

    private fun inferSemanticLabel(
        location: PreciseLocation,
        labels: List<SemanticLocationLabel>
    ): String {
        return labels
            .filter { distanceMeters(location.latitude, location.longitude, it.latitude, it.longitude) <= it.radiusMeters }
            .minByOrNull { distanceMeters(location.latitude, location.longitude, it.latitude, it.longitude) }
            ?.label
            ?: UNKNOWN_SEMANTIC_LABEL
    }

    private fun distanceMeters(lat1: Double, lon1: Double, lat2: Double, lon2: Double): Double {
        val dLat = Math.toRadians(lat2 - lat1)
        val dLon = Math.toRadians(lon2 - lon1)
        val rLat1 = Math.toRadians(lat1)
        val rLat2 = Math.toRadians(lat2)
        val a = sin(dLat / 2.0).pow(2.0) + cos(rLat1) * cos(rLat2) * sin(dLon / 2.0).pow(2.0)
        val c = 2.0 * atan2(sqrt(a), sqrt(1.0 - a))
        return EARTH_RADIUS_METERS * c
    }

    private fun normalizeLongitude(value: Double): Double {
        var normalized = value
        while (normalized > 180.0) normalized -= 360.0
        while (normalized < -180.0) normalized += 360.0
        return normalized
    }

    companion object {
        private const val KM_PER_LATITUDE_DEGREE = 111.32
        private const val EARTH_RADIUS_METERS = 6_371_000.0
        private const val UNKNOWN_SEMANTIC_LABEL = "unknown_area"
    }
}
