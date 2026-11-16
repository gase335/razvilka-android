// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package app.razvilka

/**
 * Мост к Rust-ядру (librazvilka_android.so). Имена методов совпадают с
 * JNI-символами в android-jni/src/lib.rs (Java_app_razvilka_NativeBridge_*).
 */
object NativeBridge {
    @Volatile private var loaded = false

    fun ensureLoaded() {
        if (!loaded) {
            System.loadLibrary("razvilka_android")
            loaded = true
        }
    }

    /** Каталог данных (filesDir): settings/логи/geoip.dat. Вызывать первым. */
    external fun nativeInit(filesDir: String)

    /** Полный конфиг (AppConfig в JSON). true — принят. */
    external fun nativeSetConfig(json: String): Boolean

    /** fd туннеля из VpnService.establish().getFd(). */
    external fun nativeSetTunFd(fd: Int)
    external fun nativeClearTunFd()

    external fun nativeStartTunnel()
    external fun nativeStopTunnel()
    external fun nativeStartProxy()
    external fun nativeStopProxy()

    external fun nativeIsActive(): Boolean

    /** Статус в JSON (см. android-jni do_status_json). */
    external fun nativeStatus(): String

    /** Новые строки журнала с прошлого вызова (разделены \n). */
    external fun nativePollLog(): String

    /** Ожидающие запросы капчи (JSON-массив). */
    external fun nativePollCaptcha(): String
    external fun nativeSubmitCaptcha(session: Int, result: String)

    external fun nativeShutdown()
}
