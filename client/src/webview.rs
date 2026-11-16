// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Вспомогательный процесс WebView2 (`razvilka.exe --webview captcha <режим> <url>`):
//! окно капчи VK, которое ядро запрашивает, если не решило её само (перехват
//! success_token из ответов страницы — та же логика, что в captcha.dart FOCSQ).
//! Результат печатается в stdout: RESULT|… . Вход в аккаунт VK не используется.

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use winit::application::ApplicationHandler;
use winit::event::WindowEvent;
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop};
use winit::window::{Window, WindowId};

const HOOK_JS: &str = r#"
(function(){
  if (window.__rzHooked) return; window.__rzHooked = 1;
  var send = function(t){ try { var m = /success_token\\?"\s*:\s*\\?"([0-9a-zA-Z_\-]+)/.exec(t); if (m) window.ipc.postMessage('RESULT|' + m[1]); } catch(e){} };
  var f = window.fetch;
  if (f) { window.fetch = function(){ return f.apply(this, arguments).then(function(r){ try { r.clone().text().then(send); } catch(e){} return r; }); }; }
  var o = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(){ this.addEventListener('load', function(){ try { send(this.responseText); } catch(e){} }); return o.apply(this, arguments); };
})();
"#;

fn emit(line: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

struct Helper {
    kind: String,
    url: String,
    title: String,
    deadline: Instant,
    timeout_line: String,
    window: Option<Window>,
    webview: Option<wry::WebView>,
    result: Arc<Mutex<Option<String>>>,
    web_context: wry::WebContext,
}

impl ApplicationHandler for Helper {
    fn resumed(&mut self, el: &ActiveEventLoop) {
        if self.window.is_some() {
            return;
        }
        let size = winit::dpi::LogicalSize::new(440.0, 640.0);
        let attrs = Window::default_attributes().with_title(self.title.clone()).with_inner_size(size);
        let window = match el.create_window(attrs) {
            Ok(w) => w,
            Err(e) => {
                emit(&format!("ERROR|окно: {e}"));
                el.exit();
                return;
            }
        };
        let r1 = self.result.clone();
        let mut builder = wry::WebViewBuilder::new_with_web_context(&mut self.web_context)
            .with_url(self.url.clone())
            .with_ipc_handler(move |req: wry::http::Request<String>| {
                let body = req.body().to_string();
                if body.starts_with("RESULT|") {
                    *r1.lock().unwrap() = Some(body);
                }
            });
        builder = builder.with_initialization_script(HOOK_JS);
        match builder.build(&window) {
            Ok(wv) => self.webview = Some(wv),
            Err(e) => {
                emit(&format!("ERROR|WebView2 недоступен: {e} (установите Microsoft Edge WebView2 Runtime)"));
                el.exit();
                return;
            }
        }
        self.window = Some(window);
    }

    fn window_event(&mut self, el: &ActiveEventLoop, _id: WindowId, event: WindowEvent) {
        if let WindowEvent::CloseRequested = event {
            emit("RESULT|error:closed");
            el.exit();
        }
    }

    fn about_to_wait(&mut self, el: &ActiveEventLoop) {
        if let Some(r) = self.result.lock().unwrap().take() {
            emit(&r);
            el.exit();
            return;
        }
        if Instant::now() > self.deadline {
            emit(&self.timeout_line);
            el.exit();
            return;
        }
        el.set_control_flow(ControlFlow::WaitUntil(Instant::now() + Duration::from_millis(300)));
    }
}

pub fn run(args: &[String]) -> i32 {
    let kind = args.first().cloned().unwrap_or_default();
    let (url, title, timeout, timeout_line) = match kind.as_str() {
        "captcha" => {
            let mode = args.get(1).cloned().unwrap_or_default();
            let secs = match mode.as_str() {
                "selected" => 120,
                "manual" => 60,
                _ => 45,
            };
            (args.get(2).cloned().unwrap_or_default(), "Подтвердите, что вы не робот — Развилка".to_string(), secs, "RESULT|error:timeout".to_string())
        }
        _ => {
            emit("ERROR|неизвестный режим");
            return 2;
        }
    };
    if url.is_empty() {
        emit("RESULT|error:empty");
        return 2;
    }
    let data = crate::paths::data_dir().join("webview");
    let mut helper = Helper {
        kind,
        url,
        title,
        deadline: Instant::now() + Duration::from_secs(timeout),
        timeout_line,
        window: None,
        webview: None,
        result: Arc::new(Mutex::new(None)),
        web_context: wry::WebContext::new(Some(data)),
    };
    let event_loop = match EventLoop::new() {
        Ok(e) => e,
        Err(e) => {
            emit(&format!("ERROR|{e}"));
            return 3;
        }
    };
    let _ = event_loop.run_app(&mut helper);
    0
}
