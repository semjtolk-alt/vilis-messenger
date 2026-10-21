
const http = require("http");

const PORT = process.env.PORT || 3000;
const TOKEN = process.env.TELEGRAM_BOT_TOKEN;

const page = `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vilis Messenger</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#101522;color:white;font-family:Arial,sans-serif}
header{padding:20px;background:#202b43;font-size:23px;font-weight:bold}
main{max-width:650px;margin:30px auto;padding:20px}
.card{background:#202b43;padding:22px;border-radius:18px}
input,button{padding:13px;border:0;border-radius:10px;font-size:16px}
input{width:100%;margin:10px 0;background:#303c54;color:white}
button{background:#6578ff;color:white;cursor:pointer}
#messages{margin-top:20px}
.msg{padding:12px;margin:8px 0;background:#303c54;border-radius:12px;overflow-wrap:anywhere}
</style>
</head>
<body>
<header>🔵 Vilis Messenger</header>
<main>
<div class="card">
<h2>Добро пожаловать в Vilis!</h2>
<p>Твой мессенджер уже запущен.</p>
<p>Telegram-бот: <b id="status">проверка...</b></p>
<p>Напиши сообщение в демо-чате:</p>
<div id="messages"></div>
<form id="form">
<input id="msg" placeholder="Твоё сообщение..." required>
<button>Отправить</button>
</form>
</div>
</main>
<script>
const form=document.getElementById('form');
const input=document.getElementById('msg');
const messages=document.getElementById('messages');
const history=JSON.parse(localStorage.getItem('vilis_demo')||'[]');
function draw(m){
 const d=document.createElement('div');
 d.className='msg';
 d.textContent=m;
 messages.appendChild(d);
}
history.forEach(draw);
form.addEventListener('submit',e=>{
 e.preventDefault();
 const t=input.value.trim();
 if(!t)return;
 history.push('Ты: '+t);
 draw('Ты: '+t);
 history.push('Vilis: Это демо-чат. Для общения между пользователями нужен сервер чатов.');
 draw('Vilis: Это демо-чат. Для общения между пользователями нужен сервер чатов.');
 localStorage.setItem('vilis_demo',JSON.stringify(history.slice(-100)));
 input.value='';
});
fetch('/health').then(r=>r.json()).then(d=>{
 document.getElementById('status').textContent=d.telegramConfigured?'настроен':'нужна настройка токена';
}).catch(()=>document.getElementById('status').textContent='неизвестно');
</script>
</body>
</html>`;

const server = http.createServer(async (req, res) => {
  if (req.url === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({
      status: "ok",
      telegramConfigured: Boolean(TOKEN)
    }));
  }

  if (req.url === "/" || req.url === "/index.html") {
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    return res.end(page);
  }

  res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
  res.end("Not found");
});

server.listen(PORT, "0.0.0.0", () => {
  console.log("Vilis Messenger запущен на порту " + PORT);
  if (TOKEN) startTelegramBot();
  else console.log("Добавь TELEGRAM_BOT_TOKEN в Render Environment");
});

async function telegram(method, body = {}) {
  const response = await fetch(
    "https://api.telegram.org/bot" + TOKEN + "/" + method,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    }
  );

  const data = await response.json();
  if (!data.ok) throw new Error(data.description || "Telegram API error");
  return data.result;
}

async function startTelegramBot() {
  let offset = 0;
  console.log("Запускаю Telegram-бота...");

  while (true) {
    try {
      const updates = await telegram("getUpdates", {
        offset,
        timeout: 30,
        allowed_updates: ["message"]
      });

      for (const update of updates) {
        offset = update.update_id + 1;
        const message = update.message;
        if (!message || !message.chat || !message.text) continue;

        const text = message.text.trim();
        let answer;

        if (text === "/start") {
          answer = "Привет! 👋 Добро пожаловать в Vilis Messenger!\n\nЯ Vilis Bot. Напиши сообщение, чтобы пообщаться.";
        } else if (text === "/help") {
          answer = "Команды Vilis Bot:\n/start — запуск\n/help — помощь";
        } else {
          answer = "Ты написал: " + text + "\n\nЯ Vilis Bot. Пока я работаю в демо-режиме.";
        }

        await telegram("sendMessage", {
          chat_id: message.chat.id,
          text: answer
        });

        console.log("Ответ отправлен пользователю");
      }
    } catch (error) {
      console.error("Ошибка Telegram:", error.message);
      await new Promise(resolve => setTimeout(resolve, 5000));
    }
  }
}
