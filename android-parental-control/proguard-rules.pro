# ────────────────────────────────────────────────────────────────────────────
# ProGuard / R8 rules  —  v2
# ────────────────────────────────────────────────────────────────────────────

# ── NativeBridge ─────────────────────────────────────────────────────────────
# All three callback methods are invoked from C++ via GetMethodID/CallVoidMethod.
# Do NOT let R8 rename or remove them.
-keep class com.example.parentalcontrol.NativeBridge {
    public *;
    public void onSniAllowed(java.lang.String);
    public void onSniBlocked(java.lang.String);
    public void onEchConnection(java.lang.String);
}

# ── AIDL-generated Binder stubs ──────────────────────────────────────────────
# R8 must keep all Stub inner classes and their transact/onTransact methods.
-keep class com.example.parentalcontrol.IWatchdogBridge { *; }
-keep class com.example.parentalcontrol.IWatchdogBridge$Stub { *; }
-keep class com.example.parentalcontrol.IWatchdogBridge$Stub$Proxy { *; }
-keep class com.example.parentalcontrol.IMainBridge { *; }
-keep class com.example.parentalcontrol.IMainBridge$Stub { *; }
-keep class com.example.parentalcontrol.IMainBridge$Stub$Proxy { *; }

# ── WatchdogService / MainBridgeService ──────────────────────────────────────
-keep public class com.example.parentalcontrol.WatchdogService extends android.app.Service
-keep public class com.example.parentalcontrol.MainBridgeService extends android.app.Service

# ── VPN service / Admin receiver ─────────────────────────────────────────────
-keep public class com.example.parentalcontrol.ParentalControlVpnService extends android.net.VpnService
-keep public class com.example.parentalcontrol.AdminReceiver extends android.app.admin.DeviceAdminReceiver

# ── General Android ───────────────────────────────────────────────────────────
-keepattributes *Annotation*, SourceFile, LineNumberTable, Signature, Exceptions

-keepclasseswithmembernames class * {
    native <methods>;
}

# ── Suppress noise ────────────────────────────────────────────────────────────
-dontnote kotlinx.coroutines.**
-dontwarn kotlinx.coroutines.**
-dontwarn kotlin.**
