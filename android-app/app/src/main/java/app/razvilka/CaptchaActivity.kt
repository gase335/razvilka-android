// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package app.razvilka

import android.annotation.SuppressLint
import android.graphics.Bitmap
import android.net.Uri
import android.os.Bundle
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Button
import android.widget.LinearLayout
import androidx.activity.ComponentActivity

/**
 * Решение капчи VK в WebView (режим captcha_mode = "wv"). Основной путь —
 * режим "auto": его решает само ядро без WebView, поэтому эта активность —
 * запасной/ручной вариант.
 *
 * ВНИМАНИЕ: точный формат извлечения токена зависит от текущего потока VK.
 * Исходный WebView-слой upstream csqtt в предоставленных исходниках
 * отсутствовал, поэтому здесь — рабочий каркас: по появлению в URL параметра
 * token/captcha_key/key он отправляется в ядро; иначе пользователь жмёт
 * «Готово». Возможно, потребуется подстройка под реальный ответ VK.
 */
class CaptchaActivity : ComponentActivity() {

    companion object {
        const val EXTRA_SESSION = "session"
        const val EXTRA_MODE = "mode"
        const val EXTRA_URL = "url"
        private val TOKEN_KEYS = listOf("token", "captcha_key", "key", "captcha_sid")
    }

    private var session = 0
    private var submitted = false

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        session = intent.getIntExtra(EXTRA_SESSION, 0)
        val url = intent.getStringExtra(EXTRA_URL) ?: run { finish(); return }

        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val web = WebView(this)
        val done = Button(this).apply { text = getString(R.string.action_done) }
        val cancel = Button(this).apply { text = getString(R.string.action_cancel) }

        web.settings.javaScriptEnabled = true
        web.settings.domStorageEnabled = true
        web.webViewClient = object : WebViewClient() {
            override fun onPageStarted(view: WebView?, u: String?, favicon: Bitmap?) {
                tryExtract(u)
            }
            override fun onPageFinished(view: WebView?, u: String?) {
                tryExtract(u)
            }
        }
        web.loadUrl(url)

        done.setOnClickListener {
            // Пытаемся вытащить токен из текущего URL; иначе отправляем сам URL.
            val current = web.url
            if (!tryExtract(current)) {
                submit(current ?: "")
            }
        }
        cancel.setOnClickListener { submit("error:cancelled") }

        val buttons = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        buttons.addView(done)
        buttons.addView(cancel)
        root.addView(buttons)
        root.addView(web, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.MATCH_PARENT))
        setContentView(root)
    }

    private fun tryExtract(u: String?): Boolean {
        if (u.isNullOrBlank() || submitted) return false
        val uri = try { Uri.parse(u) } catch (e: Exception) { return false }
        for (k in TOKEN_KEYS) {
            val v = uri.getQueryParameter(k)
            if (!v.isNullOrBlank()) {
                submit(v)
                return true
            }
        }
        return false
    }

    private fun submit(result: String) {
        if (submitted) return
        submitted = true
        try {
            NativeBridge.nativeSubmitCaptcha(session, result)
        } catch (e: Exception) {
            // ignore
        }
        finish()
    }

    override fun onDestroy() {
        if (!submitted) {
            try { NativeBridge.nativeSubmitCaptcha(session, "error:cancelled") } catch (e: Exception) {}
        }
        super.onDestroy()
    }
}
