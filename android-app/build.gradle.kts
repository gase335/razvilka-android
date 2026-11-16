// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
plugins {
    id("com.android.application") version "8.7.2" apply false
    id("org.jetbrains.kotlin.android") version "2.0.21" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.0.21" apply false
    // Кросс-компиляция Rust-крейта android-jni в .so под ABI Android.
    // Если версия не разрешится/не подружится с Gradle — поднимите её (0.9.x).
    id("org.mozilla.rust-android-gradle.rust-android") version "0.9.6" apply false
}
