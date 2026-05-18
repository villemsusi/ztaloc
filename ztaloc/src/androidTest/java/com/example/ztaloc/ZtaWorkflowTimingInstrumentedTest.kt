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

        val request = client.createLocationRequestForTesting(self, auth).getOrThrow()
        val response = client.processIncomingRequest(request.payload).getOrThrow()
        val result = client.processIncomingResponse(response.payload).getOrThrow()

        assertNotNull(result)

        val customPayload = """{"type":"custom","message":"hello from non-standard payload"}"""
        val encryptedPayload = client.encryptPayload(self, customPayload).getOrThrow()
        val decryptedPayload = client.decryptPayload(encryptedPayload).getOrThrow()
        assertEquals(customPayload, decryptedPayload)

        val create = requireNotNull(ZtaTiming.lastCreateLocationRequest)
        val processRequest = requireNotNull(ZtaTiming.lastProcessIncomingRequest)
        val processResponse = requireNotNull(ZtaTiming.lastProcessIncomingResponse)
        val total = create.totalMs + processRequest.totalMs + processResponse.totalMs

        println(create.toLogString())
        println(processRequest.toLogString())
        println(processResponse.toLogString())
        println("fullRequestResponseWorkflow total=${"%.3f".format(total)}ms")
    }
}
