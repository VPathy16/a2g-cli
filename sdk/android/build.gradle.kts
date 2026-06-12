/*
 * A2G Android SDK — Root Gradle build file
 *
 * This file holds shared configuration used by both :a2g and :sample.
 * Subproject-specific configuration lives in each subproject's own build.gradle.kts.
 */
plugins {
    // Declare plugins as applied=false so subprojects can apply them selectively
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.android) apply false
}
