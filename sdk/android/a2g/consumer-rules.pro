# A2G SDK consumer ProGuard rules
# These rules are applied to apps that depend on this library.

# Keep A2G public API
-keep class ai.vanaras.a2g.** { *; }
-keepnames class ai.vanaras.a2g.**

# Keep JNI bridge — the native a2g_ffi functions are found by name at runtime
-keep class ai.vanaras.a2g.NativeJniBridge { *; }
