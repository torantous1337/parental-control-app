/**
 * Module-level build.gradle.kts
 * Android 15 / API 35, NDK r27+, Kotlin 2.x
 */

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace   = "com.example.parentalcontrol"
    compileSdk  = 35

    defaultConfig {
        applicationId   = "com.example.parentalcontrol"
        minSdk          = 26          // Android 8.0 — minimum for WorkManager expedited
        targetSdk       = 35
        versionCode     = 1
        versionName     = "1.0.0"

        // NDK / CMake configuration
        externalNativeBuild {
            cmake {
                cppFlags("-std=c++17", "-fstack-protector-strong",
                         "-D_FORTIFY_SOURCE=2", "-fvisibility=hidden")
                arguments(
                    "-DANDROID_STL=c++_shared",   // shared STL to minimise .so size
                    "-DANDROID_ARM_NEON=TRUE"
                )
            }
        }

        // Only ship for 64-bit ABIs (required for Play Store new apps since 2021).
        ndk {
            abiFilters += setOf("arm64-v8a", "x86_64")
        }
    }

    externalNativeBuild {
        cmake {
            path    = file("CMakeLists.txt")
            version = "3.22.1"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled   = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            // Sign with your release keystore in CI; never commit the keystore.
            // signingConfig = signingConfigs.getByName("release")
        }
        debug {
            isDebuggable     = true
            isMinifyEnabled  = false
            // The CRC check will fail in debug because dexing changes the CRC.
            // Disable the check in debug builds via a BuildConfig flag.
            buildConfigField("boolean", "SKIP_INTEGRITY_CHECK", "true")
        }
    }

    buildFeatures {
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    packaging {
        // Keep .so files intact; don't strip debug symbols before the NDK does.
        jniLibs {
            useLegacyPackaging = false
        }
    }
}

dependencies {
    // AndroidX core
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)

    // WorkManager — expedited workers, API 26+
    implementation(libs.androidx.work.runtime.ktx)

    // Lifecycle / ViewModel (optional, for the monitoring UI)
    implementation(libs.androidx.lifecycle.runtime.ktx)

    // Coroutines
    implementation(libs.kotlinx.coroutines.android)

    // Notification compat (for pre-O notification channel compat)
    implementation(libs.androidx.core.ktx)

    // Testing
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}
