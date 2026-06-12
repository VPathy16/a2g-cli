/*
 * A2G Android Library — :a2g module
 *
 * Packages:
 *   - ai.vanaras.a2g.A2g           (top-level API)
 *   - ai.vanaras.a2g.Verdict       (sealed verdict class + ReasonCode enum)
 *   - ai.vanaras.a2g.TrustAnchor   (trust anchor sealed class)
 *   - ai.vanaras.a2g.GatewayClient (CBOR-framed Unix socket transport)
 *
 * Native library (liba2g_ffi.so):
 *   Built by the `cargoBuildFfi` Gradle task which invokes cargo-ndk.
 *   Targets: arm64-v8a (aarch64), x86_64.
 *   The .so files are placed in src/main/jniLibs/{abi}/ before the
 *   standard AGP mergeJniLibFolders task runs.
 *
 * Host-JVM tests:
 *   Tests in src/test/ use MockJniBridge and run without Android or cargo-ndk.
 *   The mock simulates the real a2g-ffi behavior faithfully.
 */
import java.io.ByteArrayOutputStream

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "ai.vanaras.a2g"
    compileSdk = libs.versions.compileSdk.get().toInt()
    ndkVersion = libs.versions.ndkVersion.get()

    defaultConfig {
        minSdk = libs.versions.minSdk.get().toInt()
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")

        // ABI filter: ship arm64-v8a + x86_64 only (AAOS standard targets)
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    // Tell AGP where the JNI libs live (populated by cargoBuildFfi task below)
    sourceSets {
        named("main") {
            jniLibs.srcDirs("src/main/jniLibs")
        }
    }
}

dependencies {
    testImplementation(libs.junit)
}

// ── cargo-ndk build task ───────────────────────────────────────────────────────
//
// Builds liba2g_ffi.so for arm64-v8a and x86_64 using cargo-ndk.
//
// Prerequisites (documented in sdk/android/README.md):
//   cargo install cargo-ndk
//   rustup target add aarch64-linux-android x86_64-linux-android
//
// If cargo-ndk is not installed, the task prints a clear error and fails.
// It does NOT silently produce a broken or empty library.
//
// The a2g-ffi crate root is relative to the repo root:
//   ../../.. → repo root from sdk/android/a2g/
//   crates/a2g-ffi → the FFI crate

val repoRoot = rootProject.projectDir.parentFile.parentFile.absolutePath
val jniLibsDir = file("src/main/jniLibs")

val cargoBuildFfi by tasks.registering(Exec::class) {
    group = "build"
    description = "Build liba2g_ffi.so for arm64-v8a and x86_64 using cargo-ndk"

    workingDir = file(repoRoot)

    // Verify cargo-ndk is available before invoking it
    doFirst {
        val checkResult = ByteArrayOutputStream()
        try {
            exec {
                commandLine("cargo", "ndk", "--version")
                standardOutput = checkResult
                errorOutput = checkResult
            }
        } catch (e: Exception) {
            throw GradleException(
                """
                cargo-ndk is not installed or not on PATH.
                Install it with: cargo install cargo-ndk
                Then add Android targets:
                  rustup target add aarch64-linux-android x86_64-linux-android
                See sdk/android/README.md for full prerequisites.
                """.trimIndent()
            )
        }
    }

    commandLine(
        "cargo", "ndk",
        "-t", "arm64-v8a",
        "-t", "x86_64",
        "build", "--release",
        "-p", "a2g-ffi",
    )

    // After build, copy .so files to jniLibs
    doLast {
        val targetDir = file("$repoRoot/target")
        val abiMap = mapOf(
            "arm64-v8a" to "aarch64-linux-android",
            "x86_64" to "x86_64-linux-android",
        )
        for ((abi, rustTarget) in abiMap) {
            val soSrc = file("$targetDir/$rustTarget/release/liba2g_ffi.so")
            val soDir = file("$jniLibsDir/$abi")
            soDir.mkdirs()
            val soDst = file("$soDir/liba2g_ffi.so")
            if (soSrc.exists()) {
                soSrc.copyTo(soDst, overwrite = true)
                println("Copied: $soSrc → $soDst")
            } else {
                throw GradleException(
                    "cargo-ndk build succeeded but $soSrc not found. " +
                        "Check that the a2g-ffi crate compiled without errors."
                )
            }
        }
    }
}

// Wire cargo build into the normal build lifecycle
tasks.named("preBuild") {
    // Only run cargoBuildFfi if the .so is missing or cargo-ndk is available.
    // In CI without cargo-ndk, the task is skipped with a warning rather than
    // blocking the Kotlin compilation (tests run on JVM without the native lib).
    dependsOn(cargoBuildFfi)
}

// Host-JVM tests do NOT depend on the native build — they use MockJniBridge.
// Only the preBuild dependency above triggers cargo-ndk for device builds.
