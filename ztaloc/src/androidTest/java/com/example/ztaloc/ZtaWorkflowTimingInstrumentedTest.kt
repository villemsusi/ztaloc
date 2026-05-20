package com.example.ztaloc

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.ztaloc.api.LocalAuthenticationResult
import com.example.ztaloc.api.PairedDevice
import com.example.ztaloc.core.DefaultZtaLocationClient
import com.example.ztaloc.core.ZtaConfig
import com.example.ztaloc.core.ZtaTiming
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ZtaWorkflowTimingInstrumentedTest {
    @Test
    fun fullRequestResponseWorkflow_logsTimings() = runBlocking {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val client = DefaultZtaLocationClient(context, ZtaConfig())
        val userId = "timing-${System.currentTimeMillis()}"

        client.setupUser(userId, "Timing Test").getOrThrow()
        val registration = client.getDeviceRegistrationInfo().getOrThrow()
        val self = PairedDevice(
            userId = registration.userId,
            displayName = registration.displayName,
            deviceId = registration.deviceId,
            signingPublicKeyB64 = registration.signingPublicKeyB64,
            encryptionPublicKeyB64 = registration.encryptionPublicKeyB64,
            pairedAtEpochMs = System.currentTimeMillis()
        )
        client.upsertPairedDevice(self, client.pairingFingerprint(self).getOrThrow()).getOrThrow()

        val auth = LocalAuthenticationResult(
            authenticated = true,
            multiFactorSatisfied = true,
            reason = "Instrumentation test bypass"
        )

        val createTimes = mutableListOf<Double>()
        val processRequestTimes = mutableListOf<Double>()
        val processResponseTimes = mutableListOf<Double>()
        val fullWorkflowTimes = mutableListOf<Double>()

        repeat(MEASURED_RUNS) { index ->
            val request = client.createLocationRequestForTesting(self, auth).getOrThrow()
            val response = client.processIncomingRequest(request.payload).getOrThrow()
            val result = client.processIncomingResponse(response.payload).getOrThrow()

            assertNotNull(result)

            val create = requireNotNull(ZtaTiming.lastCreateLocationRequest)
            val processRequest = requireNotNull(ZtaTiming.lastProcessIncomingRequest)
            val processResponse = requireNotNull(ZtaTiming.lastProcessIncomingResponse)
            val total = create.totalMs + processRequest.totalMs + processResponse.totalMs

            createTimes += create.totalMs
            processRequestTimes += processRequest.totalMs
            processResponseTimes += processResponse.totalMs
            fullWorkflowTimes += total

            println("ZTA_TIMING_RUN run=${index + 1} ${create.toLogString()}")
            println("ZTA_TIMING_RUN run=${index + 1} ${processRequest.toLogString()}")
            println("ZTA_TIMING_RUN run=${index + 1} ${processResponse.toLogString()}")
            println("ZTA_TIMING_RUN run=${index + 1} fullRequestResponseWorkflow total=${"%.3f".format(total)}ms")
        }

        val customPayload = """{"type":"custom","message":"hello from non-standard payload"}"""
        val encryptedPayload = client.encryptPayload(self, customPayload).getOrThrow()
        val decryptedPayload = client.decryptPayload(encryptedPayload).getOrThrow()
        assertEquals(customPayload, decryptedPayload)

        println("ZTA_TIMING_SUMMARY runs=$MEASURED_RUNS")
        println("ZTA_TIMING_SUMMARY ${stats("createLocationRequest", createTimes)}")
        println("ZTA_TIMING_SUMMARY ${stats("processIncomingRequest", processRequestTimes)}")
        println("ZTA_TIMING_SUMMARY ${stats("processIncomingResponse", processResponseTimes)}")
        println("ZTA_TIMING_SUMMARY ${stats("fullRequestResponseWorkflow", fullWorkflowTimes)}")
    }

    private fun stats(label: String, values: List<Double>): String {
        val mean = values.average()
        val min = values.minOrNull() ?: 0.0
        val max = values.maxOrNull() ?: 0.0
        val variance = values
            .map { value -> (value - mean) * (value - mean) }
            .average()
        val stddev = kotlin.math.sqrt(variance)
        return "$label mean=${mean.formatMs()}ms min=${min.formatMs()}ms max=${max.formatMs()}ms stddev=${stddev.formatMs()}ms"
    }

    private fun Double.formatMs(): String = "%.3f".format(this)

    private companion object {
        private const val MEASURED_RUNS = 10
    }
}
