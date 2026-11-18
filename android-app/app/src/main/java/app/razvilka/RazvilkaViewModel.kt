// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package app.razvilka

import android.app.Application
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject

/**
 * Единое состояние UI. Каждое поле — отдельный mutableStateOf, поэтому ввод в
 * текстовые поля не теряет фокус (баг №5): перерисовка одного поля не пересоздаёт
 * остальные. Поля ввода чисел хранятся строками, чтобы не стирать ввод.
 */
class RazvilkaViewModel(app: Application) : AndroidViewModel(app) {

    // ── сервер ──
    var serverName by mutableStateOf("")
    var host by mutableStateOf("")
    var port by mutableStateOf("443")
    var password by mutableStateOf("")
    var workers by mutableStateOf(27)
    var vkHashes by mutableStateOf("")
    var fingerprint by mutableStateOf("firefox")
    var clientIds by mutableStateOf("8202606,6287487")
    var captchaMode by mutableStateOf("auto")

    // ── маршрутизация ──
    var tunnelMode by mutableStateOf("blacklist")
    val list = mutableStateListOf<RouteEntry>()

    // ── прокси ──
    var proxyEnabled by mutableStateOf(false)
    var proxyPort by mutableStateOf("1080")
    var proxyListenIp by mutableStateOf("")
    var proxyAuth by mutableStateOf(false)
    var proxyUser by mutableStateOf("")
    var proxyPass by mutableStateOf("")

    // ── прочее ──
    var captureIpv6 by mutableStateOf(false)
    var autoRestart by mutableStateOf(true)
    var lanDirect by mutableStateOf(true)
    private var deviceId = ""

    // ── статус (только чтение из ядра) ──
    var tunnelState by mutableStateOf("off")
    var statusDetail by mutableStateOf("")
    var activeWorkers by mutableStateOf(0)
    var activeHashes by mutableStateOf(0)
    var upRate by mutableStateOf(0L)
    var downRate by mutableStateOf(0L)
    var proxyState by mutableStateOf("off")
    var proxyListen by mutableStateOf<String?>(null)
    var logText by mutableStateOf("")

    private val logBuffer = StringBuilder()
    private var lastUp = 0L
    private var lastDown = 0L
    private var lastTs = 0L

    val connected: Boolean get() = tunnelState == "on" || tunnelState == "starting"

    init {
        load()
        startPolling()
    }

    fun load() {
        val c = ConfigStore.load(getApplication())
        serverName = c.serverName; host = c.host; port = c.port.toString()
        password = c.password; workers = c.workers; vkHashes = c.vkHashes
        fingerprint = c.fingerprint; clientIds = c.clientIds; captchaMode = c.captchaMode
        tunnelMode = c.tunnelMode
        list.clear(); list.addAll(c.list)
        proxyEnabled = c.proxyEnabled; proxyPort = c.proxyPort.toString()
        proxyListenIp = c.proxyListenIp; proxyAuth = c.proxyAuth
        proxyUser = c.proxyUser; proxyPass = c.proxyPass
        captureIpv6 = c.captureIpv6; autoRestart = c.autoRestart; lanDirect = c.lanDirect
        deviceId = c.deviceId
    }

    fun build(): RazvilkaConfig = RazvilkaConfig(
        deviceId = deviceId,
        serverName = serverName,
        host = host,
        port = port.toIntOrNull() ?: 443,
        password = password,
        workers = workers,
        vkHashes = vkHashes,
        fingerprint = fingerprint,
        clientIds = clientIds,
        captchaMode = captchaMode,
        tunnelMode = tunnelMode,
        list = list.toMutableList(),
        proxyEnabled = proxyEnabled,
        proxyPort = proxyPort.toIntOrNull() ?: 1080,
        proxyListenIp = proxyListenIp,
        proxyAuth = proxyAuth,
        proxyUser = proxyUser,
        proxyPass = proxyPass,
        captureIpv6 = captureIpv6,
        autoRestart = autoRestart,
        lanDirect = lanDirect,
    )

    fun persist() {
        val cfg = build()
        ConfigStore.save(getApplication(), cfg)
        // Горячее применение, если ядро уже работает.
        try { NativeBridge.nativeSetConfig(cfg.toJson()) } catch (e: Exception) {}
    }

    fun applyLink(link: String): Boolean {
        val p = RazvilkaConfig.parseLink(link) ?: return false
        host = p.host; port = p.port.toString(); password = p.password
        if (p.hashes.isNotBlank()) vkHashes = p.hashes
        persist()
        return true
    }

    /** Количество введённых хешей (разделители — запятая, перенос строки, ;). */
    fun enteredHashCount(): Int =
        vkHashes.split(',', '\n', ';', ' ').count { it.trim().isNotEmpty() }

    fun applyRussiaPreset() {
        list.clear(); list.addAll(RazvilkaConfig.russiaPreset()); persist()
    }

    /** Живой тумблер прокси (ядро в этом же процессе). */
    fun toggleProxy(on: Boolean) {
        proxyEnabled = on
        persist()
        try {
            if (on) NativeBridge.nativeStartProxy() else NativeBridge.nativeStopProxy()
        } catch (e: Exception) {}
    }

    fun copyLogText(): String = logBuffer.toString()

    private fun startPolling() {
        lastTs = System.currentTimeMillis()
        viewModelScope.launch {
            while (true) {
                poll()
                delay(1000)
            }
        }
    }

    private fun poll() {
        try {
            val st = JSONObject(NativeBridge.nativeStatus())
            val tunnel = st.optJSONObject("tunnel")
            tunnelState = tunnel?.optString("state", "off") ?: "off"
            statusDetail = tunnel?.optString("detail", "") ?: ""
            val proxy = st.optJSONObject("proxy")
            proxyState = proxy?.optString("state", "off") ?: "off"
            proxyListen = st.optString("proxyListen", "").ifBlank { null }

            val sessions = st.optJSONArray("sessions") ?: JSONArray()
            var w = 0; var h = 0
            for (i in 0 until sessions.length()) {
                val s = sessions.getJSONObject(i)
                w += s.optInt("activeWorkers", 0)
                h += s.optInt("hashes", 0)
            }
            activeWorkers = w; activeHashes = h

            val totals = st.optJSONObject("totals")
            val up = totals?.optLong("vpnUp", 0) ?: 0
            val down = totals?.optLong("vpnDown", 0) ?: 0
            val now = System.currentTimeMillis()
            val dt = (now - lastTs).coerceAtLeast(1) / 1000.0
            upRate = ((up - lastUp).coerceAtLeast(0) / dt).toLong()
            downRate = ((down - lastDown).coerceAtLeast(0) / dt).toLong()
            lastUp = up; lastDown = down; lastTs = now
        } catch (e: Exception) {
        }
        try {
            val fresh = NativeBridge.nativePollLog()
            if (fresh.isNotEmpty()) {
                logBuffer.append(fresh)
                if (logBuffer.length > 20000) logBuffer.delete(0, logBuffer.length - 20000)
                logText = logBuffer.toString()
            }
        } catch (e: Exception) {
        }
    }
}
