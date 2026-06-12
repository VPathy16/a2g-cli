/*
 * A2G Android SDK — Gradle settings
 *
 * This is a standalone Gradle multi-project rooted at sdk/android/.
 * It is NOT a member of the top-level Cargo workspace.
 *
 * Projects:
 *   :a2g    — library module (ai.vanaras.a2g:a2g-android)
 *   :sample — GovernedCarClient demo application
 */
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "a2g-android-sdk"

include(":a2g")
project(":a2g").projectDir = file("a2g")

include(":sample")
project(":sample").projectDir = file("sample")
