// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package app.razvilka

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.List
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import kotlinx.coroutines.delay
import org.json.JSONArray
import kotlin.math.roundToInt

class MainActivity : ComponentActivity() {

    private val vm: RazvilkaViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        NativeBridge.ensureLoaded()
        NativeBridge.nativeInit(filesDir.absolutePath)
        ConfigStore.ensureGeoip(this)
        setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                Surface(Modifier.fillMaxSize()) { RazvilkaApp(vm) }
            }
        }
    }

    override fun onStop() {
        vm.persist()
        super.onStop()
    }
}

private data class Tab(val title: String, val icon: ImageVector)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RazvilkaApp(vm: RazvilkaViewModel) {
    val ctx = LocalContext.current
    var tab by rememberSaveable { mutableStateOf(0) }

    // Разрешение на уведомления (Android 13+).
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

    val vpnLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == android.app.Activity.RESULT_OK) startVpn(ctx)
    }

    fun connect() {
        vm.persist()
        val prepare = VpnService.prepare(ctx)
        if (prepare != null) vpnLauncher.launch(prepare) else startVpn(ctx)
    }

    fun disconnect() {
        ctx.startService(Intent(ctx, RazvilkaVpnService::class.java)
            .setAction(RazvilkaVpnService.ACTION_STOP))
    }

    // Капча (режим wv): опрашиваем и открываем WebView.
    LaunchedEffect(Unit) {
        while (true) {
            checkCaptcha(ctx)
            delay(1500)
        }
    }

    val tabs = listOf(
        Tab("Старт", Icons.Filled.PlayArrow),
        Tab("Сервер", Icons.Filled.Settings),
        Tab("Маршруты", Icons.Filled.List),
        Tab("Прокси", Icons.Filled.Share),
        Tab("Журнал", Icons.Filled.Info),
    )

    Scaffold(
        bottomBar = {
            NavigationBar {
                tabs.forEachIndexed { i, t ->
                    NavigationBarItem(
                        selected = tab == i,
                        onClick = { tab = i },
                        icon = { Icon(t.icon, contentDescription = t.title) },
                        label = { Text(t.title) },
                    )
                }
            }
        },
    ) { pad ->
        Box(Modifier.padding(pad).fillMaxSize()) {
            when (tab) {
                0 -> ConnectScreen(vm, ::connect, ::disconnect)
                1 -> ServerScreen(vm)
                2 -> RoutingScreen(vm)
                3 -> ProxyScreen(vm)
                else -> LogScreen(vm)
            }
        }
    }
}

private fun startVpn(ctx: Context) {
    val intent = Intent(ctx, RazvilkaVpnService::class.java).setAction(RazvilkaVpnService.ACTION_START)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) ctx.startForegroundService(intent)
    else ctx.startService(intent)
}

private fun stateTitle(state: String): String = when (state) {
    "on" -> "Подключено"
    "starting" -> "Подключение…"
    "stopping" -> "Отключение…"
    "failed" -> "Ошибка"
    else -> "Отключено"
}

private fun human(bytesPerSec: Long): String {
    if (bytesPerSec < 1024) return "$bytesPerSec Б/с"
    val u = listOf("КБ/с", "МБ/с", "ГБ/с")
    var v = bytesPerSec.toDouble() / 1024; var i = 0
    while (v >= 1024 && i < u.size - 1) { v /= 1024; i++ }
    return String.format("%.1f %s", v, u[i])
}

private var lastCaptchaKey = ""
private fun checkCaptcha(ctx: Context) {
    val raw = try { NativeBridge.nativePollCaptcha() } catch (e: Exception) { "[]" }
    val arr = try { JSONArray(raw) } catch (e: Exception) { JSONArray() }
    if (arr.length() == 0) return
    val req = arr.getJSONObject(0)
    val session = req.optInt("session", 0)
    val uri = req.optString("redirectUri", "")
    val key = "$session|$uri"
    if (uri.isBlank() || key == lastCaptchaKey) return
    lastCaptchaKey = key
    ctx.startActivity(Intent(ctx, CaptchaActivity::class.java)
        .putExtra(CaptchaActivity.EXTRA_SESSION, session)
        .putExtra(CaptchaActivity.EXTRA_MODE, req.optString("mode", "auto"))
        .putExtra(CaptchaActivity.EXTRA_URL, uri)
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
}

// ───────────────────────── страница 1: Старт ─────────────────────────

@Composable
private fun ConnectScreen(vm: RazvilkaViewModel, onConnect: () -> Unit, onDisconnect: () -> Unit) {
    Column(
        Modifier.fillMaxSize().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text(stateTitle(vm.tunnelState), style = MaterialTheme.typography.headlineMedium)
        if (vm.statusDetail.isNotBlank()) {
            Spacer(Modifier.height(6.dp))
            Text(vm.statusDetail, style = MaterialTheme.typography.bodyMedium)
        }
        Spacer(Modifier.height(24.dp))
        if (vm.connected) {
            Text("${vm.activeWorkers} потоков", style = MaterialTheme.typography.titleLarge)
            Spacer(Modifier.height(4.dp))
            Text("↑ ${human(vm.upRate)}   ↓ ${human(vm.downRate)}",
                style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(32.dp))
            Button(onClick = onDisconnect, modifier = Modifier.fillMaxWidth().height(64.dp),
                colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)) {
                Text("Отключить", style = MaterialTheme.typography.titleLarge)
            }
        } else {
            Spacer(Modifier.height(32.dp))
            Button(onClick = onConnect, modifier = Modifier.fillMaxWidth().height(64.dp)) {
                Text("Подключить", style = MaterialTheme.typography.titleLarge)
            }
        }
    }
}

// ───────────────────────── страница 2: Сервер ─────────────────────────

@Composable
private fun ServerScreen(vm: RazvilkaViewModel) {
    val ctx = LocalContext.current
    var link by remember { mutableStateOf("") }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("Настройка подключения", style = MaterialTheme.typography.titleLarge)

        OutlinedTextField(link, { link = it }, label = { Text("Ссылка csqtt://") },
            modifier = Modifier.fillMaxWidth(), singleLine = true)
        Button(enabled = link.isNotBlank(), onClick = {
            if (vm.applyLink(link)) { link = ""; toast(ctx, "Применено") } else toast(ctx, "Не ссылка csqtt://")
        }) { Text("Применить ссылку") }

        Field("Адрес (host)", vm.host) { vm.host = it }
        Field("Порт", vm.port, number = true) { vm.port = it.filter { c -> c.isDigit() } }
        Field("Пароль", vm.password) { vm.password = it }

        OutlinedTextField(vm.vkHashes, { vm.vkHashes = it },
            label = { Text("Хеши звонков VK") },
            modifier = Modifier.fillMaxWidth().heightIn(min = 90.dp))
        Text("Введено хешей: ${vm.enteredHashCount()}" +
            if (vm.connected) " · используется: ${vm.activeHashes}" else "",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant)

        Spacer(Modifier.height(4.dp))
        Text("Потоков: ${vm.workers}", style = MaterialTheme.typography.titleMedium)
        Slider(
            value = vm.workers.toFloat(),
            onValueChange = { vm.workers = (it / 9f).roundToInt() * 9 },
            valueRange = 9f..189f,
            steps = 19,
        )
        Text("кратно 9; один поток ≈ один стрим звонка",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant)

        Choice("Отпечаток TLS", listOf("firefox", "chrome", "edge", "opera"), vm.fingerprint) { vm.fingerprint = it }
        Choice("Капча", listOf("auto", "rjs", "wv"), vm.captchaMode) { vm.captchaMode = it }
        Field("client_ids", vm.clientIds) { vm.clientIds = it }
        SwitchRow("Перехватывать IPv6", vm.captureIpv6) { vm.captureIpv6 = it }
        SwitchRow("Автоперезапуск сервера", vm.autoRestart) { vm.autoRestart = it }
        Spacer(Modifier.height(24.dp))
    }
}

// ───────────────────────── страница 3: Маршруты ─────────────────────────

@Composable
private fun RoutingScreen(vm: RazvilkaViewModel) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("Маршрутизация", style = MaterialTheme.typography.titleLarge)
        val modes = listOf("full" to "Всё через VPN", "blacklist" to "Чёрный список", "whitelist" to "Белый список")
        modes.forEach { (v, label) ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                RadioButton(selected = vm.tunnelMode == v, onClick = { vm.tunnelMode = v })
                Text(label)
            }
        }
        if (vm.tunnelMode != "full") {
            Text(if (vm.tunnelMode == "blacklist") "Напрямую, мимо VPN:" else "Только через VPN:",
                style = MaterialTheme.typography.bodyMedium)
            vm.list.forEachIndexed { i, e ->
                Row(verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    KindDropdown(e.kind) { vm.list[i] = e.copy(kind = it) }
                    OutlinedTextField(e.value, { vm.list[i] = e.copy(value = it) },
                        modifier = Modifier.weight(1f), singleLine = true,
                        placeholder = { Text("значение") })
                    IconButton(onClick = { vm.list.removeAt(i) }) { Text("✕") }
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { vm.list.add(RouteEntry()) }) { Text("Добавить") }
                OutlinedButton(onClick = { vm.applyRussiaPreset() }) { Text("Пресет: Россия") }
            }
        }
        Spacer(Modifier.height(24.dp))
    }
}

// ───────────────────────── страница 4: Прокси ─────────────────────────

@Composable
private fun ProxyScreen(vm: RazvilkaViewModel) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("Прокси-сервер (SOCKS5)", style = MaterialTheme.typography.titleLarge)
        Text("Поднимает SOCKS5-прокси в локальной сети: другие устройства (или приложения) " +
            "ходят в интернет через этот телефон и его туннель. Работает вместе с VPN.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
        SwitchRow("Включить прокси", vm.proxyEnabled) { vm.toggleProxy(it) }
        if (vm.proxyEnabled && vm.proxyListen != null) {
            Text("Слушает: ${vm.proxyListen}  (${proxyStateTitle(vm.proxyState)})",
                style = MaterialTheme.typography.bodyMedium)
        }
        Field("Порт", vm.proxyPort, number = true) { vm.proxyPort = it.filter { c -> c.isDigit() } }
        Field("IP прослушивания (пусто = Wi-Fi адрес)", vm.proxyListenIp) { vm.proxyListenIp = it }
        SwitchRow("Логин/пароль", vm.proxyAuth) { vm.proxyAuth = it }
        if (vm.proxyAuth) {
            Field("Логин", vm.proxyUser) { vm.proxyUser = it }
            Field("Пароль", vm.proxyPass) { vm.proxyPass = it }
        }
        Spacer(Modifier.height(24.dp))
    }
}

private fun proxyStateTitle(s: String) = when (s) {
    "on" -> "работает"; "starting" -> "запуск…"; "failed" -> "ошибка"; else -> "выключен"
}

// ───────────────────────── страница 5: Журнал ─────────────────────────

@Composable
private fun LogScreen(vm: RazvilkaViewModel) {
    val ctx = LocalContext.current
    Column(Modifier.fillMaxSize().padding(16.dp)) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically) {
            Text("Журнал", style = MaterialTheme.typography.titleLarge)
            OutlinedButton(onClick = {
                val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                cm.setPrimaryClip(ClipData.newPlainText("Razvilka log", vm.copyLogText()))
                toast(ctx, "Журнал скопирован")
            }) { Text("Копировать") }
        }
        Spacer(Modifier.height(8.dp))
        val scroll = rememberScrollState()
        LaunchedEffect(vm.logText) { scroll.scrollTo(scroll.maxValue) }
        Text(vm.logText.ifBlank { "—" },
            style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
            modifier = Modifier.fillMaxWidth().weight(1f).verticalScroll(scroll))
    }
}

// ───────────────────────── общие элементы ─────────────────────────

@Composable
private fun Field(label: String, value: String, number: Boolean = false, onChange: (String) -> Unit) {
    OutlinedTextField(
        value, onChange, label = { Text(label) },
        modifier = Modifier.fillMaxWidth(), singleLine = true,
        keyboardOptions = if (number) KeyboardOptions(keyboardType = KeyboardType.Number) else KeyboardOptions.Default,
    )
}

@Composable
private fun SwitchRow(label: String, value: Boolean, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically) {
        Text(label, Modifier.weight(1f))
        Switch(checked = value, onCheckedChange = onChange)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun Choice(label: String, options: List<String>, value: String, onChange: (String) -> Unit) {
    var open by remember { mutableStateOf(false) }
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically) {
        Text(label)
        Box {
            OutlinedButton(onClick = { open = true }) { Text(value) }
            DropdownMenu(open, { open = false }) {
                options.forEach { o -> DropdownMenuItem(text = { Text(o) }, onClick = { onChange(o); open = false }) }
            }
        }
    }
}

@Composable
private fun KindDropdown(value: String, onChange: (String) -> Unit) {
    val kinds = listOf("domain" to "Домен", "ip" to "IP", "country" to "Страна")
    var open by remember { mutableStateOf(false) }
    Box {
        OutlinedButton(onClick = { open = true }) { Text(kinds.firstOrNull { it.first == value }?.second ?: "Домен") }
        DropdownMenu(open, { open = false }) {
            kinds.forEach { (v, label) -> DropdownMenuItem(text = { Text(label) }, onClick = { onChange(v); open = false }) }
        }
    }
}

private fun toast(ctx: Context, msg: String) = Toast.makeText(ctx, msg, Toast.LENGTH_SHORT).show()
