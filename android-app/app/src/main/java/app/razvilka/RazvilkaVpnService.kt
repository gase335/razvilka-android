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
import org.json.JSONObject

/**
 * VPN-служба Развилки. Поднимает TUN через VpnService.Builder, отдаёт его fd в
 * Rust-ядро и держит туннель в foreground.
 *
 * addDisallowedApplication(собственный пакет) выводит трафик приложения (сокеты
 * ядра к TURN, «прямые» соединения движка) из туннеля — обход VPN без protect().
 */
class RazvilkaVpnService : VpnService() {

    private var tun: ParcelFileDescriptor? = null
    @Volatile private var statsThread: Thread? = null
    @Volatile private var lastUp = 0L
    @Volatile private var lastDown = 0L
    @Volatile private var lastTs = 0L

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
        // intent == null → служба воскрешена системой после убийства. НЕ
        // поднимаем VPN сами (иначе туннель встаёт без рабочего ядра и глушит
        // весь трафик) — просто гасимся.
        when (intent?.action) {
            null -> {
                stopSelfCleanly()
                return START_NOT_STICKY
            }
            ACTION_STOP -> {
                stopTunnel()
                return START_NOT_STICKY
            }
            else -> startTunnel()
        }
        // NOT_STICKY: система не перезапускает службу с null-интентом.
        return START_NOT_STICKY
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
            stopSelfCleanly()
            return
        }
        NativeBridge.nativeSetConfig(cfg.toJson())

        val builder = Builder()
            .setSession("Razvilka")
            .setMtu(MTU)
            .addAddress(TUN_V4, 30)
            .addDnsServer(DNS_V4)
            .addRoute("0.0.0.0", 1)
            .addRoute("128.0.0.0", 1)
        if (cfg.captureIpv6) {
            builder.addAddress(TUN_V6, 120)
            builder.addRoute("::", 1)
            builder.addRoute("8000::", 1)
        }
        try {
            builder.addDisallowedApplication(packageName)
        } catch (e: Exception) {
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
        if (cfg.proxyEnabled) {
            try { NativeBridge.nativeStartProxy() } catch (e: Exception) {}
        }
        running = true
        startStatsLoop()
    }

    private fun stopTunnel() {
        if (!running && tun == null) {
            stopSelfCleanly()
            return
        }
        running = false
        statsThread?.interrupt()
        statsThread = null
        // Блокирующий стоп (ядро отпустит dup fd туннеля) — в фоне, не на main.
        Thread {
            try {
                NativeBridge.nativeStopProxy()
            } catch (e: Exception) {}
            try {
                NativeBridge.nativeStopTunnel()   // блокирует до закрытия fd ядром
                NativeBridge.nativeClearTunFd()
            } catch (e: Exception) {}
            try {
                tun?.close()
            } catch (e: Exception) {}
            tun = null
            stopSelfCleanly()
        }.start()
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
        statsThread?.interrupt()
        statsThread = null
        if (running || tun != null) {
            // Синхронно освобождаем туннель, чтобы не оставить мёртвый интерфейс.
            running = false
            try { NativeBridge.nativeStopProxy() } catch (e: Exception) {}
            try {
                NativeBridge.nativeStopTunnel()
                NativeBridge.nativeClearTunFd()
            } catch (e: Exception) {}
            try { tun?.close() } catch (e: Exception) {}
            tun = null
        }
        super.onDestroy()
    }

    override fun onRevoke() {
        stopTunnel()
        super.onRevoke()
    }

    // ───────────────────────── живое уведомление (#3) ─────────────────────────

    private fun startStatsLoop() {
        lastUp = 0; lastDown = 0; lastTs = System.currentTimeMillis()
        val t = Thread {
            while (running && !Thread.currentThread().isInterrupted) {
                try {
                    Thread.sleep(2000)
                } catch (e: InterruptedException) {
                    break
                }
                if (!running) break
                try {
                    val st = JSONObject(NativeBridge.nativeStatus())
                    val sessions = st.optJSONArray("sessions")
                    var workers = 0L
                    if (sessions != null) {
                        for (i in 0 until sessions.length()) {
                            workers += sessions.getJSONObject(i).optLong("activeWorkers", 0)
                        }
                    }
                    val totals = st.optJSONObject("totals")
                    val up = totals?.optLong("vpnUp", 0) ?: 0
                    val down = totals?.optLong("vpnDown", 0) ?: 0
                    val now = System.currentTimeMillis()
                    val dt = (now - lastTs).coerceAtLeast(1) / 1000.0
                    val upRate = ((up - lastUp).coerceAtLeast(0) / dt).toLong()
                    val downRate = ((down - lastDown).coerceAtLeast(0) / dt).toLong()
                    lastUp = up; lastDown = down; lastTs = now
                    val text = "${workers} потоков · ↑ ${rate(upRate)} ↓ ${rate(downRate)}"
                    updateNotification(text)
                } catch (e: Exception) {
                }
            }
        }
        t.isDaemon = true
        statsThread = t
        t.start()
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
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE,
        )
        val stop = PendingIntent.getService(
            this, 1,
            Intent(this, RazvilkaVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOnlyAlertOnce(true)
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

    private fun rate(bytesPerSec: Long): String {
        if (bytesPerSec < 1024) return "$bytesPerSec Б/с"
        val u = listOf("КБ/с", "МБ/с", "ГБ/с")
        var v = bytesPerSec.toDouble() / 1024
        var i = 0
        while (v >= 1024 && i < u.size - 1) { v /= 1024; i++ }
        return String.format("%.1f %s", v, u[i])
    }
}
