# ZtaLoc Android SDK

ZtaLoc is an Android library for zero trust-based location sharing. It handles
local device setup, key generation, paired-device storage, signed/encrypted
location requests, trust evaluation, and policy-based location disclosure.

## 1. Add the SDK

During local development, include the library module from your app's
`settings.gradle.kts`:

```kotlin
include(":ztaloc")
project(":ztaloc").projectDir = File("../ztaloc/ztaloc")
```

Then add it to the app module:

```kotlin
dependencies {
    implementation(project(":ztaloc"))
}
```

## 2. Initialize

Call once from your `Application.onCreate()`:

```kotlin
import com.example.ztaloc.api.ZtaObj
import com.example.ztaloc.core.ZtaConfig

class MyApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        ZtaObj.initialize(
            applicationContext,
            ZtaConfig(
                knownHoursStart = 6,
                knownHoursEnd = 23,
                preciseThreshold = 90,
                approximateThreshold = 80,
                semanticThreshold = 70,
                minimumCategoryScore = 10,
                approximateMaxOffsetKm = 20.0,
                semanticLabelRadiusMeters = 100.0
            )
        )
    }
}
```

All `ZtaConfig` values are optional. Use them when your app needs different
policy thresholds, expected request hours, request freshness, approximate
location radius, semantic label radius, or trust category weights.

Default policy:

- score below 70: deny
- fewer than 10 points in any category: deny
- 70-79: semantic location
- 80-89: approximate location
- 90-100: precise location

By default, trust signal point values are adaptive: every unconfigured signal
gets an equal share of the 100 point budget. If all 12 current signals are used,
each signal is worth about 8.33 points. Apps may override one or more signal
point values in `ZtaConfig`; the remaining unconfigured signals share the
remaining budget equally.

Current trust signals:

- device trust: registered device, device integrity, OS version, hardware-backed
  keys, secure lock
- context trust: trusted network, expected hours, request freshness
- behavior trust: normal request rate, no repeated failures, plausible movement
- trust recency: time since the last trusted request

Trust recency measures time since the last trusted request with the same paired
device. It starts at 10 raw points and loses 1 raw point per month. At 10 months
or older it contributes 0 raw points. If there is no prior trusted request, the
paired-device timestamp is used as the initial trusted timestamp.

## 3. Set Up the Local User

After your app registers or logs in a user:

```kotlin
ZtaObj.setupUser(
    userId = user.id.toString(),
    displayName = "${user.firstName} ${user.lastName}"
).getOrThrow()
```

Export this device's public registration info:

```kotlin
val registrationInfo = ZtaObj.getDeviceRegistrationInfo().getOrThrow()
```

Share `registrationInfo` with another device through your app's pairing flow.
Only public keys and public device metadata are included.

## 4. Pair Devices

Convert a scanned or received device registration into a `PairedDevice`, then
store it:

```kotlin
ZtaObj.upsertPairedDevice(
    PairedDevice(
        userId = registrationInfo.userId,
        displayName = registrationInfo.displayName,
        deviceId = registrationInfo.deviceId,
        signingPublicKeyB64 = registrationInfo.signingPublicKeyB64,
        encryptionPublicKeyB64 = registrationInfo.encryptionPublicKeyB64,
        pairedAtEpochMs = System.currentTimeMillis()
    )
).getOrThrow()
```

Recommended pairing UX:

1. Device A displays `getDeviceRegistrationInfo()` as a QR code.
2. Device B scans, shows display name/device id/key fingerprints, then stores A.
3. Device B displays its registration QR code.
4. Device A scans, confirms, then stores B.

Remove a paired device:

```kotlin
ZtaObj.removePairedDevice(deviceId).getOrThrow()
```

## 5. Configure Semantic Labels

Semantic labels map precise coordinates to a label within a fixed 100m radius.

```kotlin
ZtaObj.upsertSemanticLocationLabel(
    label = "home",
    latitude = 59.4370,
    longitude = 24.7536
).getOrThrow()
```

List or remove labels:

```kotlin
val labels = ZtaObj.listSemanticLocationLabels().getOrThrow()
ZtaObj.removeSemanticLocationLabel("home").getOrThrow()
```

## 6. Create a Location Request

Requester device:

```kotlin
val target = ZtaObj.listPairedDevices().getOrThrow().first()
val request = ZtaObj.createLocationRequest(target, activity).getOrThrow()
```

Send `request.payload` to the target device through your backend or relay.
The payload is already signed and encrypted by the SDK.
The Activity-based overload prompts the requester with Android's device
credential UI, using the user's configured PIN, password, pattern, or biometric.
If local authentication fails, no request is created.

## 7. Process a Request

Target device:

```kotlin
val response = ZtaObj.processIncomingRequest(requestPayload).getOrThrow()
```

Send `response.payload` back to the requester through your backend or relay.
The response is signed and encrypted by the SDK.
The target does not manually approve the request. The SDK verifies the request,
evaluates the policy, and returns the enforced `decision`, `exposure`,
`trustScore`, and `reason` on `OutgoingResponse` so the wrapping application can
notify the target user about the request and policy outcome.

## 8. Process a Response

Requester device:

```kotlin
val result = ZtaObj.processIncomingResponse(responsePayload).getOrThrow()
```

`result.locationPayload` contains one of:

- precise coordinates
- randomized approximate coordinates
- a semantic label
- `null` when access is denied or step-up is required

## 9. Required App Responsibilities

Your app must provide:

- Account management and any server-side user authentication.
- Android location permission requests.
- QR or other pairing UI.
- Backend/relay delivery for encrypted request and response payloads.
- UI for trusted devices and semantic labels.

The SDK does not currently provide its own relay client, QR scanner, account
system, or UI.
For request-time Zero Trust checks, prefer the Activity-based request methods so
the SDK can use Android's local credential prompt as part of the policy flow.

## 10. Notes

- Approximate location randomly offsets latitude and longitude independently by
  up to 20km.
- Semantic location returns the closest configured label within 100m, or
  `unknown_area`.
- Requests older than 60 seconds are rejected.
- Duplicate processed request session ids are rejected.
- Payloads are signed and encrypted end-to-end between paired devices.
