// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package app.razvilka

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.UUID

/** Хранение UI-конфига в SharedPreferences и подготовка geoip.dat. */
object ConfigStore {
    private const val PREFS = "razvilka"
    private const val KEY = "config"

    fun load(ctx: Context): RazvilkaConfig {
        val prefs = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val raw = prefs.getString(KEY, null) ?: return default()
        return try {
            fromStorageJson(JSONObject(raw))
        } catch (e: Exception) {
            default()
        }
    }

    fun save(ctx: Context, cfg: RazvilkaConfig) {
        val prefs = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        prefs.edit().putString(KEY, toStorageJson(cfg).toString()).apply()
    }

    private fun default(): RazvilkaConfig = RazvilkaConfig(
        deviceId = UUID.randomUUID().toString(),
        list = RazvilkaConfig.russiaPreset(),
    )

    private fun toStorageJson(c: RazvilkaConfig): JSONObject {
        val list = JSONArray()
        for (e in c.list) {
            list.put(
                JSONObject()
                    .put("kind", e.kind)
                    .put("value", e.value)
                    .put("enabled", e.enabled)
                    .put("id", e.id),
            )
        }
        return JSONObject()
            .put("deviceId", c.deviceId)
            .put("serverName", c.serverName)
            .put("host", c.host)
            .put("port", c.port)
            .put("password", c.password)
            .put("workers", c.workers)
            .put("vkHashes", c.vkHashes)
            .put("fingerprint", c.fingerprint)
            .put("clientIds", c.clientIds)
            .put("captchaMode", c.captchaMode)
            .put("tunnelMode", c.tunnelMode)
            .put("captureIpv6", c.captureIpv6)
            .put("autoRestart", c.autoRestart)
            .put("lanDirect", c.lanDirect)
            .put("proxyEnabled", c.proxyEnabled)
            .put("proxyPort", c.proxyPort)
            .put("proxyListenIp", c.proxyListenIp)
            .put("proxyAuth", c.proxyAuth)
            .put("proxyUser", c.proxyUser)
            .put("proxyPass", c.proxyPass)
            .put("list", list)
    }

    private fun fromStorageJson(o: JSONObject): RazvilkaConfig {
        val list = mutableListOf<RouteEntry>()
        val arr = o.optJSONArray("list") ?: JSONArray()
        for (i in 0 until arr.length()) {
            val e = arr.getJSONObject(i)
            list.add(
                RouteEntry(
                    kind = e.optString("kind", "domain"),
                    value = e.optString("value", ""),
                    enabled = e.optBoolean("enabled", true),
                    id = e.optString("id", UUID.randomUUID().toString()),
                ),
            )
        }
        return RazvilkaConfig(
            deviceId = o.optString("deviceId", UUID.randomUUID().toString()),
            serverName = o.optString("serverName", ""),
            host = o.optString("host", ""),
            port = o.optInt("port", 443),
            password = o.optString("password", ""),
            workers = o.optInt("workers", 27),
            vkHashes = o.optString("vkHashes", ""),
            fingerprint = o.optString("fingerprint", "firefox"),
            clientIds = o.optString("clientIds", "8202606,6287487"),
            captchaMode = o.optString("captchaMode", "auto"),
            tunnelMode = o.optString("tunnelMode", "blacklist"),
            list = list,
            proxyEnabled = o.optBoolean("proxyEnabled", false),
            proxyPort = o.optInt("proxyPort", 1080),
            proxyListenIp = o.optString("proxyListenIp", ""),
            proxyAuth = o.optBoolean("proxyAuth", false),
            proxyUser = o.optString("proxyUser", ""),
            proxyPass = o.optString("proxyPass", ""),
            captureIpv6 = o.optBoolean("captureIpv6", false),
            autoRestart = o.optBoolean("autoRestart", true),
            lanDirect = o.optBoolean("lanDirect", true),
        )
    }

    /** Копирует geoip.dat из assets в filesDir (нужен правилам «Страна»). */
    fun ensureGeoip(ctx: Context) {
        val dst = File(ctx.filesDir, "geoip.dat")
        if (dst.exists() && dst.length() > 0) return
        try {
            ctx.assets.open("geoip.dat").use { input ->
                dst.outputStream().use { output -> input.copyTo(output) }
            }
        } catch (e: Exception) {
            // Нет geoip.dat в assets — правила «Страна» не будут работать.
        }
    }
}
