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

class MyApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        ZtaObj.initialize(applicationContext)
    }
}
```

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
val request = ZtaObj.createLocationRequest(target).getOrThrow()
```

Send `request.payload` to the target device through your backend or relay.
The payload is already signed and encrypted by the SDK.

## 7. Process a Request

Target device:

```kotlin
val response = ZtaObj.processIncomingRequest(requestPayload).getOrThrow()
```

Send `response.payload` back to the requester through your backend or relay.
The response is signed and encrypted by the SDK.

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

- User authentication and account management.
- Android location permission requests.
- QR or other pairing UI.
- Backend/relay delivery for encrypted request and response payloads.
- UI for trusted devices and semantic labels.

The SDK does not currently provide its own relay client, QR scanner, account
system, or UI.

## 10. Notes

- Approximate location randomly offsets latitude and longitude independently by
  up to 20km.
- Semantic location returns the closest configured label within 100m, or
  `unknown_area`.
- Requests older than 60 seconds are rejected.
- Duplicate processed request session ids are rejected.
- Payloads are signed and encrypted end-to-end between paired devices.
