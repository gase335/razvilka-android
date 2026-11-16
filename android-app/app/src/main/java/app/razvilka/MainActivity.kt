// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package app.razvilka

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import kotlinx.coroutines.delay
import org.json.JSONArray
import org.json.JSONObject

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        NativeBridge.ensureLoaded()
        NativeBridge.nativeInit(filesDir.absolutePath)
        ConfigStore.ensureGeoip(this)
        setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                Surface(modifier = Modifier.fillMaxSize()) {
                    RazvilkaApp()
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RazvilkaApp() {
    val ctx = androidx.compose.ui.platform.LocalContext.current
    var cfg by remember { mutableStateOf(ConfigStore.load(ctx)) }
    val entries = remember { mutableStateListOf<RouteEntry>().apply { addAll(cfg.list) } }

    var statusTitle by remember { mutableStateOf("Отключено") }
    var tunnelState by remember { mutableStateOf("off") }
    var detail by remember { mutableStateOf("") }
    var speed by remember { mutableStateOf("") }
    val logBuffer = remember { StringBuilder() }
    var logText by remember { mutableStateOf("") }

    // Запрос разрешения на уведомления (Android 13+).
    val notifLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) {}
    LaunchedEffect(Unit) {
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            notifLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    // Согласие VpnService.prepare → затем запуск службы.
    val vpnLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == android.app.Activity.RESULT_OK) {
            startVpn(ctx)
        }
    }

    fun persist() {
        cfg.list = entries.toMutableList()
        ConfigStore.save(ctx, cfg)
    }

    fun connect() {
        persist()
        NativeBridge.nativeSetConfig(cfg.toJson())
        val prepare = VpnService.prepare(ctx)
        if (prepare != null) {
            vpnLauncher.launch(prepare)
        } else {
            startVpn(ctx)
        }
    }

    fun disconnect() {
        val intent = Intent(ctx, RazvilkaVpnService::class.java).setAction(RazvilkaVpnService.ACTION_STOP)
        ctx.startService(intent)
    }

    // Опрос статуса, журнала и капчи раз в секунду.
    LaunchedEffect(Unit) {
        while (true) {
            try {
                val st = JSONObject(NativeBridge.nativeStatus())
                val tunnel = st.optJSONObject("tunnel")
                tunnelState = tunnel?.optString("state", "off") ?: "off"
                detail = tunnel?.optString("detail", "") ?: ""
                val sessions = st.optJSONArray("sessions") ?: JSONArray()
                statusTitle = when {
                    sessions.length() > 0 -> sessions.getJSONObject(0).optString("statusTitle", stateTitle(tunnelState))
                    else -> stateTitle(tunnelState)
                }
                val totals = st.optJSONObject("totals")
                if (totals != null) {
                    val up = totals.optLong("vpnUp"); val down = totals.optLong("vpnDown")
                    speed = "↑ ${human(up)}  ↓ ${human(down)}"
                }
            } catch (e: Exception) { /* ядро ещё не готово */ }

            val fresh = try { NativeBridge.nativePollLog() } catch (e: Exception) { "" }
            if (fresh.isNotEmpty()) {
                logBuffer.append(fresh)
                // держим последние ~12000 символов
                if (logBuffer.length > 12000) logBuffer.delete(0, logBuffer.length - 12000)
                logText = logBuffer.toString()
            }
            checkCaptcha(ctx)
            delay(1000)
        }
    }

    val connected = tunnelState == "on" || tunnelState == "starting"
    val scroll = rememberScrollState()

    Scaffold(
        topBar = { TopAppBar(title = { Text("Развилка") }) },
    ) { pad ->
        Column(
            modifier = Modifier
                .padding(pad)
                .padding(16.dp)
                .fillMaxSize()
                .verticalScroll(scroll),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            StatusCard(statusTitle, detail, speed, connected, tunnelState,
                onConnect = { connect() }, onDisconnect = { disconnect() })

            ServerCard(cfg, onChange = { cfg = it.copy() }, onApplyLink = { link ->
                RazvilkaConfig.parseLink(link)?.let { p ->
                    cfg = cfg.copy(host = p.host, port = p.port, password = p.password,
                        vkHashes = if (p.hashes.isNotBlank()) p.hashes else cfg.vkHashes)
                }
            })

            RoutingCard(cfg, entries, onModeChange = { cfg = cfg.copy(tunnelMode = it) })

            SettingsCard(cfg, onChange = { cfg = it.copy() })

            LogCard(logText)

            Text(
                "Один сервер за раз · правила «Программа» на Android не поддерживаются",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(24.dp))
        }
    }
}

private fun startVpn(ctx: android.content.Context) {
    val intent = Intent(ctx, RazvilkaVpnService::class.java).setAction(RazvilkaVpnService.ACTION_START)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
        ctx.startForegroundService(intent)
    } else {
        ctx.startService(intent)
    }
}

private fun stateTitle(state: String): String = when (state) {
    "on" -> "Подключено"
    "starting" -> "Подключение…"
    "stopping" -> "Отключение…"
    "failed" -> "Ошибка"
    else -> "Отключено"
}

private fun human(bytes: Long): String {
    if (bytes < 1024) return "$bytes Б"
    val units = listOf("КБ", "МБ", "ГБ", "ТБ")
    var v = bytes.toDouble() / 1024
    var i = 0
    while (v >= 1024 && i < units.size - 1) { v /= 1024; i++ }
    return String.format("%.1f %s", v, units[i])
}

private var lastCaptchaKey = ""
private fun checkCaptcha(ctx: android.content.Context) {
    val raw = try { NativeBridge.nativePollCaptcha() } catch (e: Exception) { "[]" }
    val arr = try { JSONArray(raw) } catch (e: Exception) { JSONArray() }
    if (arr.length() == 0) return
    val req = arr.getJSONObject(0)
    val session = req.optInt("session", 0)
    val mode = req.optString("mode", "auto")
    val uri = req.optString("redirectUri", "")
    val key = "$session|$uri"
    if (uri.isBlank() || key == lastCaptchaKey) return
    lastCaptchaKey = key
    val intent = Intent(ctx, CaptchaActivity::class.java)
        .putExtra(CaptchaActivity.EXTRA_SESSION, session)
        .putExtra(CaptchaActivity.EXTRA_MODE, mode)
        .putExtra(CaptchaActivity.EXTRA_URL, uri)
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    ctx.startActivity(intent)
}

// ───────────────────────── карточки ─────────────────────────

@Composable
private fun StatusCard(
    title: String, detail: String, speed: String, connected: Boolean, state: String,
    onConnect: () -> Unit, onDisconnect: () -> Unit,
) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(title, style = MaterialTheme.typography.headlineSmall)
            if (detail.isNotBlank()) Text(detail, style = MaterialTheme.typography.bodyMedium)
            if (speed.isNotBlank() && connected) Text(speed, style = MaterialTheme.typography.bodyMedium)
            if (connected) {
                Button(onClick = onDisconnect, modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)) {
                    Text("Отключить")
                }
            } else {
                Button(onClick = onConnect, modifier = Modifier.fillMaxWidth()) {
                    Text("Подключить")
                }
            }
        }
    }
}

@Composable
private fun ServerCard(cfg: RazvilkaConfig, onChange: (RazvilkaConfig) -> Unit, onApplyLink: (String) -> Unit) {
    var link by remember { mutableStateOf("") }
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Сервер csqtt", style = MaterialTheme.typography.titleMedium)
            OutlinedTextField(link, { link = it }, label = { Text("Ссылка csqtt://") },
                modifier = Modifier.fillMaxWidth(), singleLine = true)
            Button(onClick = { onApplyLink(link); link = "" }, enabled = link.isNotBlank()) {
                Text("Применить ссылку")
            }
            OutlinedTextField(cfg.host, { onChange(cfg.copy(host = it)) }, label = { Text("Адрес (host)") },
                modifier = Modifier.fillMaxWidth(), singleLine = true)
            OutlinedTextField(cfg.port.toString(), { onChange(cfg.copy(port = it.toIntOrNull() ?: 0)) },
                label = { Text("Порт") }, modifier = Modifier.fillMaxWidth(), singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number))
            OutlinedTextField(cfg.password, { onChange(cfg.copy(password = it)) }, label = { Text("Пароль") },
                modifier = Modifier.fillMaxWidth(), singleLine = true)
            OutlinedTextField(cfg.vkHashes, { onChange(cfg.copy(vkHashes = it)) },
                label = { Text("Хеши звонков VK (через запятую/строки)") },
                modifier = Modifier.fillMaxWidth().heightIn(min = 80.dp))
            OutlinedTextField(cfg.workers.toString(), { onChange(cfg.copy(workers = it.toIntOrNull() ?: 9)) },
                label = { Text("Потоков (кратно 9)") }, modifier = Modifier.fillMaxWidth(), singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number))
        }
    }
}

@Composable
private fun RoutingCard(cfg: RazvilkaConfig, entries: MutableList<RouteEntry>, onModeChange: (String) -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Туннелирование", style = MaterialTheme.typography.titleMedium)
            val modes = listOf("full" to "Всё через VPN", "blacklist" to "Чёрный список", "whitelist" to "Белый список")
            Column {
                for ((value, label) in modes) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        RadioButton(selected = cfg.tunnelMode == value, onClick = { onModeChange(value) })
                        Text(label)
                    }
                }
            }
            if (cfg.tunnelMode != "full") {
                val listLabel = if (cfg.tunnelMode == "blacklist") "Напрямую (мимо VPN):" else "Через VPN:"
                Text(listLabel, style = MaterialTheme.typography.bodyMedium)
                entries.forEachIndexed { i, e ->
                    Row(verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        KindDropdown(e.kind) { entries[i] = e.copy(kind = it) }
                        OutlinedTextField(e.value, { entries[i] = e.copy(value = it) },
                            modifier = Modifier.weight(1f), singleLine = true,
                            placeholder = { Text("значение") })
                        IconButton(onClick = { entries.removeAt(i) }) { Text("✕") }
                    }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = { entries.add(RouteEntry()) }) { Text("Добавить") }
                    OutlinedButton(onClick = {
                        entries.clear(); entries.addAll(RazvilkaConfig.russiaPreset())
                    }) { Text("Пресет: Россия") }
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun KindDropdown(value: String, onChange: (String) -> Unit) {
    val kinds = listOf("domain" to "Домен", "ip" to "IP", "country" to "Страна")
    var open by remember { mutableStateOf(false) }
    Box {
        OutlinedButton(onClick = { open = true }) {
            Text(kinds.firstOrNull { it.first == value }?.second ?: "Домен")
        }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            for ((v, label) in kinds) {
                DropdownMenuItem(text = { Text(label) }, onClick = { onChange(v); open = false })
            }
        }
    }
}

@Composable
private fun SettingsCard(cfg: RazvilkaConfig, onChange: (RazvilkaConfig) -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Настройки", style = MaterialTheme.typography.titleMedium)
            SwitchRow("Перехватывать IPv6", cfg.captureIpv6) { onChange(cfg.copy(captureIpv6 = it)) }
            SwitchRow("Автоперезапуск сервера", cfg.autoRestart) { onChange(cfg.copy(autoRestart = it)) }
            SwitchRow("Локальные сети — напрямую", cfg.lanDirect) { onChange(cfg.copy(lanDirect = it)) }
            ChoiceRow("Отпечаток TLS", listOf("firefox", "chrome", "edge", "opera"), cfg.fingerprint) {
                onChange(cfg.copy(fingerprint = it))
            }
            ChoiceRow("Капча", listOf("auto", "rjs", "wv"), cfg.captchaMode) {
                onChange(cfg.copy(captchaMode = it))
            }
        }
    }
}

@Composable
private fun SwitchRow(label: String, value: Boolean, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically) {
        Text(label)
        Switch(checked = value, onCheckedChange = onChange)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ChoiceRow(label: String, options: List<String>, value: String, onChange: (String) -> Unit) {
    var open by remember { mutableStateOf(false) }
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically) {
        Text(label)
        Box {
            OutlinedButton(onClick = { open = true }) { Text(value) }
            DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
                for (o in options) {
                    DropdownMenuItem(text = { Text(o) }, onClick = { onChange(o); open = false })
                }
            }
        }
    }
}

@Composable
private fun LogCard(logText: String) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Text("Журнал", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))
            val scroll = rememberScrollState()
            LaunchedEffect(logText) { scroll.scrollTo(scroll.maxValue) }
            Text(
                logText.ifBlank { "—" },
                style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                maxLines = 400,
                overflow = TextOverflow.Clip,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = 260.dp)
                    .verticalScroll(scroll),
            )
        }
    }
}
