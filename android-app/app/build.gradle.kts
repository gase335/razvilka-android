// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.mozilla.rust-android-gradle.rust-android")
}

android {
    namespace = "app.razvilka"
    compileSdk = 35

    defaultConfig {
        applicationId = "app.razvilka"
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = "1.0.0"
    }

    // NDK, которым собирается Rust-крейт. Укажите установленную у вас версию
    // (Android Studio → SDK Manager → NDK (Side by side)).
    ndkVersion = "27.1.12297006"

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
    }
    packaging {
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
    }
}

// ─── Rust: сборка librazvilka_android.so для всех ABI и укладка в jniLibs ───
// Требует: установленный NDK (ndkVersion выше) и rust-таргеты Android:
//   rustup target add aarch64-linux-android armv7-linux-androideabi \
//                     x86_64-linux-android i686-linux-android
cargo {
    // Путь к Rust-крейту JNI-моста относительно каталога этого модуля (app/).
    module = "../../android-jni"
    libname = "razvilka_android"
    // ABI сборки. По умолчанию только arm64 (почти все телефоны/планшеты с ~2017):
    // каждый ABI заново компилирует aws-lc/rustls/tokio, поэтому меньше ABI = в разы
    // быстрее. Переопределить: ./gradlew assembleDebug -PrustTargets=arm64,x86_64
    //   arm64 — реальные устройства, x86_64 — эмулятор, arm — старые телефоны, x86 — старый эмулятор.
    targets = (project.findProperty("rustTargets") as String?)?.split(",")
        ?: listOf("arm64")
    profile = "release"
    // minSdk для нативной части — совпадает с android.defaultConfig.minSdk.
    apiLevel = 24
}

// Rust собирается до упаковки нативных библиотек.
tasks.matching { it.name.matches(Regex("merge.*JniLibFolders")) }.configureEach {
    dependsOn("cargoBuild")
}
tasks.named("preBuild").configure {
    dependsOn("cargoBuild")
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.6")
    implementation("androidx.activity:activity-compose:1.9.3")

    val composeBom = platform("androidx.compose:compose-bom:2024.10.00")
    implementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.6")
}
