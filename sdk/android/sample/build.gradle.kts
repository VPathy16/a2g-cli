/*
 * A2G Demo Application — :sample module
 *
 * GovernedCarClient demo activity showing ALLOW / DENY / ESCALATE paths.
 * Targets AAOS (minSdk 29).
 */
plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "ai.vanaras.a2g.sample"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        applicationId = "ai.vanaras.a2g.sample"
        minSdk = libs.versions.minSdk.get().toInt()
        targetSdk = libs.versions.targetSdk.get().toInt()
        versionCode = 1
        versionName = "0.2.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation(project(":a2g"))

    // AAOS Car libraries — provided at runtime by the AAOS platform.
    // The 'compileOnly' scope avoids packaging them into the APK since they
    // are available on AAOS system images but not in the standard SDK.
    compileOnly(libs.android.car)

    testImplementation(libs.junit)
}
