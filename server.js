
const express = require("express");
const { Pool } = require("pg");
const crypto = require("node:crypto");
const path = require("node:path");

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.SESSION_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;

app.use(express.json({ limit: "20kb" }));
app.use(express.static(path.join(__dirname, "public")));

if (!SECRET || !DATABASE_URL) {
  console.error("Set SESSION_SECRET and DATABASE_URL in Render.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: /localhost|127\.0\.0\.1/.test(DATABASE_URL)
    ? false
    : { rejectUnauthorized: false }
});

const AVATARS = ["🙂", "😎", "🐱", "🐼", "🦊", "🚀", "👾", "⭐"];

function sign(payload) {
  return crypto.createHmac("sha256", SECRET)
    .update(payload)
    .digest("base64url");
}

function createToken(userId) {
  const payload = Buffer.from(JSON.stringify({
    id: userId,
    exp: Date.now() + 7 * 24 * 60 * 60 * 1000
  })).toString("base64url");

  return payload + "." + sign(payload);
}

function verifyToken(token) {
  try {
    const parts = token.split(".");
    if (parts.length !== 2) return null;

    const [payload, signature] = parts;
    const expected = Buffer.from(sign(payload));
    const actual = Buffer.from(signature);

    if (
      expected.length !== actual.length ||
      !crypto.timingSafeEqual(expected, actual)
    ) return null;

    const data = JSON.parse(
      Buffer.from(payload, "base64url").toString("utf8")
    );

    if (!Number.isInteger(data.id) || data.exp < Date.now()) {
      return null;
    }

    return data;
  } catch {
    return null;
  }
}

function passwordHash(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (error, key) => {
      if (error) return reject(error);
      resolve(key.toString("hex"));
    });
  });
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    avatar: user.avatar
  };
}

async function auth(req, res, next) {
  try {
    const token = (req.headers.authorization || "")
      .replace(/^Bearer\s+/i, "");

    const session = verifyToken(token);
    if (!session) {
      return res.status(401).json({
        error: "Сессия истекла. Войди снова."
      });
    }

    const result = await pool.query(
      "SELECT id, username, avatar FROM users WHERE id = $1",
      [session.id]
    );

    if (!result.rows[0]) {
      return res.status(401).json({ error: "Пользователь не найден" });
    }

    req.user = result.rows[0];
    next();
  } catch (error) {
    next(error);
  }
}

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(24) UNIQUE NOT NULL,
      salt TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      avatar VARCHAR(16) NOT NULL DEFAULT '🙂',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      username VARCHAR(24) NOT NULL,
      avatar VARCHAR(16) NOT NULL,
      text VARCHAR(2000) NOT NULL,
      room VARCHAR(40) NOT NULL DEFAULT 'general',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS messages_room_id_idx
      ON messages(room, id);
  `);
}

app.get("/health", (req, res) => {
  res.json({ ok: true, app: "Vilis Messenger 2.0" });
});

app.post("/api/register", async (req, res, next) => {
  try {
    const username = String(req.body.username || "")
      .trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!/^[a-z0-9_]{3,24}$/.test(username)) {
      return res.status(400).json({
        error: "Имя: 3–24 английских символа, цифры или _"
      });
    }

    if (password.length < 8 || password.length > 128) {
      return res.status(400).json({
        error: "Пароль должен быть длиной от 8 до 128 символов"
      });
    }

    const salt = crypto.randomBytes(16).toString("hex");
    const hashed = await passwordHash(password, salt);

    const result = await pool.query(
      `INSERT INTO users(username, salt, password_hash)
       VALUES($1, $2, $3)
       RETURNING id, username, avatar`,
      [username, salt, hashed]
    );

    const user = result.rows[0];

    res.json({
      token: createToken(user.id),
      user: publicUser(user)
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        error: "Это имя уже занято. Выбери другое."
      });
    }
    next(error);
  }
});

app.post("/api/login", async (req, res, next) => {
  try {
    const username = String(req.body.username || "")
      .trim().toLowerCase();
    const password = String(req.body.password || "");

    const result = await pool.query(
      "SELECT * FROM users WHERE username = $1",
      [username]
    );

    const user = result.rows[0];
    if (!user) {
      return res.status(401).json({
        error: "Неверное имя или пароль"
      });
    }

    const hashed = await passwordHash(password, user.salt);
    const a = Buffer.from(hashed, "hex");
    const b = Buffer.from(user.password_hash, "hex");

    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return res.status(401).json({
        error: "Неверное имя или пароль"
      });
    }

    res.json({
      token: createToken(user.id),
      user: publicUser(user)
    });
  } catch (error) {
    next(error);
  }
});

app.get("/api/me", auth, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

app.post("/api/profile", auth, async (req, res, next) => {
  try {
    const avatar = String(req.body.avatar || "");

    if (!AVATARS.includes(avatar)) {
      return res.status(400).json({ error: "Неизвестный аватар" });
    }

    await pool.query(
      "UPDATE users SET avatar = $1 WHERE id = $2",
      [avatar, req.user.id]
    );

    res.json({ ok: true, avatar });
  } catch (error) {
    next(error);
  }
});

app.get("/api/messages", auth, async (req, res, next) => {
  try {
    const after = Math.max(0, Number(req.query.after) || 0);

    const result = await pool.query(
      `SELECT id, username, avatar, text, room, created_at
       FROM messages
       WHERE room = 'general' AND id > $1
       ORDER BY id ASC
       LIMIT 100`,
      [after]
    );

    res.json({ messages: result.rows });
  } catch (error) {
    next(error);
  }
});

app.post("/api/messages", auth, async (req, res, next) => {
  try {
    const text = String(req.body.text || "").trim();

    if (!text || text.length > 2000) {
      return res.status(400).json({
        error: "Сообщение должно содержать от 1 до 2000 символов"
      });
    }

    const result = await pool.query(
      `INSERT INTO messages
        (user_id, username, avatar, text, room)
       VALUES ($1, $2, $3, $4, 'general')
       RETURNING id, username, avatar, text, room, created_at`,
      [req.user.id, req.user.username, req.user.avatar, text]
    );

    res.json({ message: result.rows[0] });
  } catch (error) {
    next(error);
  }
});

app.post("/api/ai", auth, async (req, res) => {
  const apiKey = process.env.OPENAI_API_KEY;

  if (!apiKey) {
    return res.status(503).json({
      error: "Vilis AI не подключён. Добавь OPENAI_API_KEY в Render."
    });
  }

  const prompt = String(req.body.text || "").trim();

  if (!prompt || prompt.length > 4000) {
    return res.status(400).json({
      error: "Введи вопрос длиной до 4000 символов"
    });
  }

  try {
    const response = await fetch(
      "https://api.openai.com/v1/chat/completions",
      {
        method: "POST",
        headers: {
          Authorization: "Bearer " + apiKey,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          model: process.env.OPENAI_MODEL || "gpt-4.1-mini",
          messages: [
            {
              role: "system",
              content: "Ты Vilis AI, дружелюбный помощник. Отвечай на языке пользователя."
            },
            { role: "user", content: prompt }
          ]
        })
      }
    );

    const data = await response.json();

    if (!response.ok) {
      console.error("AI provider returned status", response.status);
      return res.status(502).json({
        error: "Ошибка Vilis AI. Проверь API-ключ, баланс и модель."
      });
    }

    res.json({
      answer: data.choices?.[0]?.message?.content ||
        "Не удалось получить ответ."
    });
  } catch (error) {
    console.error("AI request failed:", error.message);
    res.status(502).json({
      error: "Не удалось связаться с Vilis AI"
    });
  }
});

/* Telegram bot: /start and /help.
   It does not synchronize Telegram messages with the website. */
async function telegramCall(method, body) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  if (!token) return null;

  const response = await fetch(
    "https://api.telegram.org/bot" + token + "/" + method,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    }
  );

  const data = await response.json();
  if (!data.ok) {
    throw new Error(data.description || "Telegram API error");
  }
  return data.result;
}

async function startTelegramBot() {
  if (!process.env.TELEGRAM_BOT_TOKEN) {
    console.log("Telegram bot disabled: no TELEGRAM_BOT_TOKEN");
    return;
  }

  let offset = 0;
  console.log("Telegram bot polling started");

  while (true) {
    try {
      const updates = await telegramCall("getUpdates", {
        offset,
        timeout: 25,
        allowed_updates: ["message"]
      });

      for (const update of updates || []) {
        offset = update.update_id + 1;

        const message = update.message;
        if (!message || !message.chat) continue;

        const text = String(message.text || "").trim();
        const command = text.split(/\s+/)[0].split("@")[0];

        if (command === "/start") {
          await telegramCall("sendMessage", {
            chat_id: message.chat.id,
            text:
              "👋 Добро пожаловать в Vilis Messenger!\n\n" +
              "Команды:\n/start — начать\n/help — помощь\n\n" +
              "Веб-версия: открой адрес своего сайта на Render."
          });
        } else if (command === "/help") {
          await telegramCall("sendMessage", {
            chat_id: message.chat.id,
            text: "Vilis Bot работает. Используй /start для приветствия."
          });
        }
      }
    } catch (error) {
      console.error("Telegram bot error:", error.message);
      await new Promise(resolve => setTimeout(resolve, 5000));
    }
  }
}

app.use((error, req, res, next) => {
  console.error(error);
  if (res.headersSent) return next(error);
  res.status(500).json({ error: "Ошибка сервера" });
});

async function main() {
  await initDb();

  app.listen(PORT, "0.0.0.0", () => {
    console.log("Vilis Messenger running on port " + PORT);
  });

  startTelegramBot();
}

main().catch(error => {
  console.error("Startup failed:", error);
  process.exit(1);
});
