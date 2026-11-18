// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package app.razvilka

import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/** Запись белого/чёрного списка split-tunnel. */
data class RouteEntry(
    var kind: String = "domain",   // domain | ip | country  (app не поддерживается на Android)
    var value: String = "",
    var enabled: Boolean = true,
    val id: String = UUID.randomUUID().toString(),
)

/**
 * Конфиг Razvilka в терминах, которыми оперирует UI. Сериализуется в JSON,
 * совместимый с serde-структурой AppConfig (поля с #[serde(default)] можно
 * опускать — Rust подставит значения по умолчанию).
 *
 * На Android одновременно активен один сервер (встроенный режим ядра).
 */
data class RazvilkaConfig(
    var deviceId: String = UUID.randomUUID().toString(),
    // Сервер csqtt
    var serverName: String = "",
    var host: String = "",
    var port: Int = 443,
    var password: String = "",
    var workers: Int = 27,
    // VK
    var vkHashes: String = "",
    var fingerprint: String = "firefox",
    var clientIds: String = "8202606,6287487",
    var captchaMode: String = "auto",      // auto | rjs | wv
    // Split-tunnel
    var tunnelMode: String = "blacklist",  // full | whitelist | blacklist
    var list: MutableList<RouteEntry> = mutableListOf(),
    // Прокси-сервер (SOCKS5/SOCKS4/HTTP на одном порту) для устройств в LAN
    var proxyEnabled: Boolean = false,
    var proxyPort: Int = 1080,
    var proxyListenIp: String = "",   // пусто = адрес в локальной сети (Wi-Fi)
    var proxyAuth: Boolean = false,
    var proxyUser: String = "",
    var proxyPass: String = "",
    // Прочее
    var captureIpv6: Boolean = false,
    var autoRestart: Boolean = true,
    var lanDirect: Boolean = true,
) {
    fun toJson(): String {
        val root = JSONObject()
        root.put("device_id", deviceId)
        root.put("capture_ipv6", captureIpv6)
        root.put("auto_restart", autoRestart)
        root.put("lan_direct", lanDirect)
        root.put("merge_same_server", true)
        root.put("tunnel_on", true)
        root.put("proxy_on", proxyEnabled)

        val profile = JSONObject()
            .put("id", "server-1")
            .put("name", if (serverName.isBlank()) "$host:$port" else serverName)
            .put("enabled", true)
            .put("host", host.trim())
            .put("port", port)
            .put("password", password)
            .put("workers", workers)
            .put("hashes", "")
            .put("weight", 1)
        root.put("profiles", JSONArray().put(profile))

        root.put(
            "vk",
            JSONObject()
                .put("hashes", vkHashes.trim())
                .put("fingerprint", fingerprint)
                .put("client_ids", clientIds)
                .put("captcha_mode", captchaMode),
        )

        val entries = JSONArray()
        for (e in list) {
            if (e.value.isBlank()) continue
            entries.put(
                JSONObject()
                    .put("id", e.id)
                    .put("enabled", e.enabled)
                    .put("kind", e.kind)
                    .put("value", e.value.trim())
                    .put("server", JSONObject.NULL),
            )
        }
        val tunnel = JSONObject()
            .put("mode", tunnelMode)
            .put("server", JSONObject.NULL)
        // Список кладём в ключ активного режима (как читает active_list в Rust).
        when (tunnelMode) {
            "whitelist" -> tunnel.put("whitelist", entries).put("blacklist", JSONArray())
            "blacklist" -> tunnel.put("blacklist", entries).put("whitelist", JSONArray())
            else -> tunnel.put("whitelist", JSONArray()).put("blacklist", JSONArray())
        }
        root.put("tunnel", tunnel)

        root.put(
            "dns",
            JSONObject()
                .put("hijack_all", true)
                .put("filter_aaaa_for_tunnel", true),
        )
        root.put(
            "proxy",
            JSONObject()
                .put("listen_ip", proxyListenIp.trim())
                .put("port", proxyPort)
                .put("auth", proxyAuth)
                .put("username", proxyUser)
                .put("password", proxyPass),
        )
        return root.toString()
    }

    /** Результат разбора ссылки csqtt:// */
    data class ParsedServer(val host: String, val port: Int, val password: String, val hashes: String)

    companion object {
        /**
         * Разбор ссылки csqtt:// (оба формата FOCSQ: v2 connect?… и legacy
         * password@host:port). Параллель client/src/app_config.rs::parse_link.
         */
        fun parseLink(link: String): ParsedServer? {
            val rest = link.trim().removePrefix("csqtt://")
            if (rest == link.trim()) return null
            if (rest.startsWith("connect?")) {
                var query = rest.removePrefix("connect?")
                // Известные ключи могут идти без '&' (особенность FOCSQ).
                for (key in listOf("host", "peer", "password", "hashes")) {
                    query = query.replaceFirst("$key=", "&$key=")
                }
                var host = ""; var peer = ""; var password = ""; var hashes = ""; var ver = ""
                for (pair in query.split('&')) {
                    if (pair.isEmpty()) continue
                    val idx = pair.indexOf('=')
                    val k = if (idx >= 0) pair.substring(0, idx) else pair
                    val v = urlDecode(if (idx >= 0) pair.substring(idx + 1) else "")
                    when (k) {
                        "host" -> host = v
                        "peer" -> peer = v
                        "password" -> password = v
                        "hashes" -> hashes = v
                        "v" -> ver = v
                    }
                }
                if (ver != "2") return null
                val port = peer.toIntOrNull() ?: return null
                if (host.isEmpty() || password.isEmpty() || port <= 0) return null
                return ParsedServer(host, port, password, hashes)
            }
            val at = rest.lastIndexOf('@')
            if (at <= 0 || at == rest.length - 1) return null
            val password = urlDecode(rest.substring(0, at))
            val addr = rest.substring(at + 1)
            val (host, portStr) = if (addr.startsWith("[")) {
                val close = addr.indexOf(']'); if (close < 0) return null
                addr.substring(1, close) to addr.substring(close + 1).removePrefix(":")
            } else {
                val parts = addr.split(':'); if (parts.size != 2) return null
                parts[0] to parts[1]
            }
            val port = portStr.toIntOrNull() ?: return null
            if (host.isEmpty() || port <= 0) return null
            return ParsedServer(host, port, password, "")
        }

        private fun urlDecode(s: String): String = try {
            java.net.URLDecoder.decode(s, "UTF-8")
        } catch (e: Exception) {
            s
        }

        /** Пресет «Россия напрямую»: российские зоны и IP идут мимо VPN. */
        fun russiaPreset(): MutableList<RouteEntry> = mutableListOf(
            RouteEntry("country", "RU"),
            RouteEntry("domain", "ru"),
            RouteEntry("domain", "su"),
            RouteEntry("domain", "рф"),
            RouteEntry("domain", "москва"),
            RouteEntry("domain", "дети"),
            RouteEntry("domain", "орг"),
        )
    }
}
