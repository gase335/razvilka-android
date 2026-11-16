// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package app.razvilka

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat

/**
 * VPN-служба Razvilka. Поднимает TUN через VpnService.Builder, отдаёт его fd в
 * Rust-ядро и держит туннель в foreground.
 *
 * Ключевой момент: addDisallowedApplication(собственный пакет) выводит трафик
 * самого приложения (TURN-сокеты ядра, «прямые» соединения движка) из туннеля —
 * поэтому обход VPN работает без per-socket protect().
 */
class RazvilkaVpnService : VpnService() {

    private var tun: ParcelFileDescriptor? = null

    companion object {
        const val ACTION_START = "app.razvilka.action.START"
        const val ACTION_STOP = "app.razvilka.action.STOP"
        private const val CHANNEL_ID = "razvilka_vpn"
        private const val NOTIF_ID = 1

        // Адреса туннеля — совпадают с RouterAddrs::default() в Rust.
        private const val TUN_V4 = "172.19.0.1"
        private const val DNS_V4 = "172.19.0.2"
        private const val TUN_V6 = "fdfe:dcba:9876::1"
        private const val MTU = 1300

        @Volatile
        var running = false
            private set
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopTunnel()
                return START_NOT_STICKY
            }
            else -> startTunnel()
        }
        return START_STICKY
    }

    private fun startTunnel() {
        if (running) return
        createChannel()
        startForegroundCompat(buildNotification(getString(R.string.state_connecting)))

        NativeBridge.ensureLoaded()
        NativeBridge.nativeInit(filesDir.absolutePath)
        ConfigStore.ensureGeoip(this)
        val cfg = ConfigStore.load(this)
        if (cfg.host.isBlank() || cfg.password.isBlank() || cfg.vkHashes.isBlank()) {
            // Нечего подключать — не поднимаем туннель.
            stopSelfCleanly()
            return
        }
        NativeBridge.nativeSetConfig(cfg.toJson())

        val builder = Builder()
            .setSession("Razvilka")
            .setMtu(MTU)
            .addAddress(TUN_V4, 30)
            .addDnsServer(DNS_V4)
            // Половинные маршруты перехватывают любой дефолт (как на десктопе).
            .addRoute("0.0.0.0", 1)
            .addRoute("128.0.0.0", 1)
        if (cfg.captureIpv6) {
            builder.addAddress(TUN_V6, 120)
            builder.addRoute("::", 1)
            builder.addRoute("8000::", 1)
        }
        // Вывести собственный трафик приложения из туннеля (обход для TURN/VK).
        try {
            builder.addDisallowedApplication(packageName)
        } catch (e: Exception) {
            // Пакет не найден — не критично, но обход может не работать.
        }
        builder.setBlocking(true)

        val pfd = try {
            builder.establish()
        } catch (e: Exception) {
            null
        }
        if (pfd == null) {
            stopSelfCleanly()
            return
        }
        tun = pfd
        NativeBridge.nativeSetTunFd(pfd.fd)
        NativeBridge.nativeStartTunnel()
        running = true
        updateNotification(getString(R.string.state_connected))
    }

    private fun stopTunnel() {
        if (!running && tun == null) {
            stopSelfCleanly()
            return
        }
        try {
            NativeBridge.nativeStopTunnel()
            NativeBridge.nativeClearTunFd()
        } catch (e: Exception) {
            // ignore
        }
        // Ядро владеет собственным dup fd и само его закроет; закрываем свой PFD.
        try {
            tun?.close()
        } catch (e: Exception) {
            // ignore
        }
        tun = null
        running = false
        stopSelfCleanly()
    }

    private fun stopSelfCleanly() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
        stopSelf()
    }

    override fun onDestroy() {
        if (running || tun != null) {
            stopTunnel()
        }
        super.onDestroy()
    }

    override fun onRevoke() {
        // Пользователь отозвал разрешение VPN в системе.
        stopTunnel()
        super.onRevoke()
    }

    // ───────────────────────── уведомление ─────────────────────────

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val mgr = getSystemService(NotificationManager::class.java)
            if (mgr.getNotificationChannel(CHANNEL_ID) == null) {
                val ch = NotificationChannel(
                    CHANNEL_ID,
                    getString(R.string.notif_channel),
                    NotificationManager.IMPORTANCE_LOW,
                )
                ch.setShowBadge(false)
                mgr.createNotificationChannel(ch)
            }
        }
    }

    private fun buildNotification(text: String): Notification {
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val stop = PendingIntent.getService(
            this,
            1,
            Intent(this, RazvilkaVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .setContentIntent(open)
            .addAction(0, getString(R.string.action_disconnect), stop)
            .build()
    }

    private fun updateNotification(text: String) {
        val mgr = getSystemService(NotificationManager::class.java)
        mgr.notify(NOTIF_ID, buildNotification(text))
    }

    private fun startForegroundCompat(notification: Notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIF_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIF_ID, notification)
        }
    }
}
