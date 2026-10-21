
const express = require("express");
const path = require("path");
const http = require("http");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const { Server } = require("socket.io");
const TelegramBot = require("node-telegram-bot-api");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;
const SECRET = process.env.SESSION_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const OPENAI_MODEL = process.env.OPENAI_MODEL || "gpt-4o-mini";
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;

app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

const db = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL && /render\.com/i.test(DATABASE_URL)
    ? { rejectUnauthorized: false }
    : undefined
});

async function initDB() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      username VARCHAR(24) UNIQUE NOT NULL,
      display_name VARCHAR(60) NOT NULL,
      password_hash TEXT NOT NULL,
      avatar_url TEXT DEFAULT '',
      telegram_id BIGINT UNIQUE,
      link_code VARCHAR(6),
      link_expires TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS chats (
      id BIGSERIAL PRIMARY KEY,
      title VARCHAR(80) DEFAULT '',
      type VARCHAR(12) NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS chat_members (
      chat_id BIGINT REFERENCES chats(id) ON DELETE CASCADE,
      user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
      PRIMARY KEY (chat_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY,
      chat_id BIGINT REFERENCES chats(id) ON DELETE CASCADE,
      user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
      sender_name VARCHAR(60) NOT NULL,
      text TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS messages_chat_idx
      ON messages(chat_id, id);
  `);

  const general = await db.query(
    "SELECT id FROM chats WHERE type='general' LIMIT 1"
  );

  if (!general.rowCount) {
    await db.query(
      "INSERT INTO chats(title, type) VALUES($1, $2)",
      ["Общий чат", "general"]
    );
  }
}

function tokenFor(user) {
  if (!SECRET) throw new Error("SESSION_SECRET не настроен");

  return jwt.sign(
    { id: String(user.id), username: user.username },
    SECRET,
    { expiresIn: "14d" }
  );
}

function safeUser(user) {
  return {
    id: String(user.id),
    username: user.username,
    displayName: user.display_name,
    avatarUrl: user.avatar_url || "",
    telegramLinked: Boolean(user.telegram_id)
  };
}

async function authenticate(req, res, next) {
  try {
    const token = (req.headers.authorization || "")
      .replace(/^Bearer\s+/i, "");

    if (!token || !SECRET) {
      return res.status(401).json({ error: "Войди в аккаунт." });
    }

    const payload = jwt.verify(token, SECRET);
    const result = await db.query(
      `SELECT id, username, display_name, password_hash,
              avatar_url, telegram_id
       FROM users WHERE id=$1`,
      [payload.id]
    );

    if (!result.rowCount) {
      return res.status(401).json({ error: "Аккаунт не найден." });
    }

    req.user = result.rows[0];
    next();
  } catch {
    return res.status(401).json({
      error: "Сессия завершена. Войди заново."
    });
  }
}

async function isChatMember(chatId, userId) {
  const result = await db.query(
    "SELECT 1 FROM chat_members WHERE chat_id=$1 AND user_id=$2",
    [chatId, userId]
  );
  return result.rowCount > 0;
}

async function saveMessage(chatId, userId, senderName, text) {
  const result = await db.query(
    `INSERT INTO messages(chat_id, user_id, sender_name, text)
     VALUES($1, $2, $3, $4)
     RETURNING id, chat_id, user_id, sender_name, text, created_at`,
    [chatId, userId || null, senderName, String(text).slice(0, 4000)]
  );

  const row = result.rows[0];

  const message = {
    id: String(row.id),
    chatId: String(row.chat_id),
    userId: row.user_id ? String(row.user_id) : null,
    senderName: row.sender_name,
    text: row.text,
    createdAt: row.created_at
  };

  io.to("chat:" + chatId).emit("new_message", message);
  return message;
}

// Проверка сервера
app.get("/health", (req, res) => {
  res.json({ ok: true, app: "Vilis Messenger" });
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Регистрация
app.post("/api/register", async (req, res) => {
  try {
    const username = String(req.body.username || "")
      .trim().toLowerCase();
    const displayName = String(
      req.body.displayName || username
    ).trim().slice(0, 60);
    const password = String(req.body.password || "");

    if (!/^[a-z0-9_]{3,24}$/.test(username)) {
      return res.status(400).json({
        error: "Логин: 3–24 символа, латинские буквы, цифры и _."
      });
    }

    if (password.length < 8 || password.length > 128) {
      return res.status(400).json({
        error: "Пароль должен содержать от 8 до 128 символов."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await db.query(
      `INSERT INTO users(username, display_name, password_hash)
       VALUES($1, $2, $3)
       RETURNING id, username, display_name, avatar_url, telegram_id`,
      [username, displayName || username, passwordHash]
    );

    const user = result.rows[0];

    const general = await db.query(
      "SELECT id FROM chats WHERE type='general' LIMIT 1"
    );

    if (general.rowCount) {
      await db.query(
        `INSERT INTO chat_members(chat_id, user_id)
         VALUES($1, $2) ON CONFLICT DO NOTHING`,
        [general.rows[0].id, user.id]
      );
    }

    res.json({ token: tokenFor(user), user: safeUser(user) });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ error: "Логин уже занят." });
    }

    console.error("Register:", error);
    res.status(500).json({ error: "Не удалось зарегистрироваться." });
  }
});

// Вход
app.post("/api/login", async (req, res) => {
  try {
    const username = String(req.body.username || "")
      .trim().toLowerCase();
    const password = String(req.body.password || "");

    const result = await db.query(
      "SELECT * FROM users WHERE username=$1",
      [username]
    );

    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(
      password, user.password_hash
    ))) {
      return res.status(401).json({
        error: "Неверный логин или пароль."
      });
    }

    res.json({ token: tokenFor(user), user: safeUser(user) });
  } catch (error) {
    console.error("Login:", error);
    res.status(500).json({ error: "Ошибка входа." });
  }
});

// Мой профиль
app.get("/api/me", authenticate, (req, res) => {
  res.json({ user: safeUser(req.user) });
});

app.patch("/api/me", authenticate, async (req, res) => {
  try {
    const name = String(req.body.displayName || "")
      .trim().slice(0, 60);
    const avatar = String(req.body.avatarUrl || "")
      .trim().slice(0, 500);

    if (!name) {
      return res.status(400).json({ error: "Укажи имя профиля." });
    }

    if (avatar && !/^https:\/\//i.test(avatar)) {
      return res.status(400).json({
        error: "Ссылка на аватар должна начинаться с https://"
      });
    }

    const result = await db.query(
      `UPDATE users SET display_name=$1, avatar_url=$2
       WHERE id=$3
       RETURNING id, username, display_name, avatar_url, telegram_id`,
      [name, avatar, req.user.id]
    );

    res.json({ user: safeUser(result.rows[0]) });
  } catch (error) {
    console.error("Profile:", error);
    res.status(500).json({ error: "Не удалось сохранить профиль." });
  }
});

// Поиск пользователей
app.get("/api/users", authenticate, async (req, res) => {
  try {
    const q = String(req.query.q || "").trim().slice(0, 40);

    const result = await db.query(
      `SELECT id, username, display_name, avatar_url
       FROM users
       WHERE id<>$1
         AND ($2='' OR username ILIKE $3 OR display_name ILIKE $3)
       ORDER BY display_name
       LIMIT 50`,
      [req.user.id, q, "%" + q + "%"]
    );

    res.json({
      users: result.rows.map(u => ({
        id: String(u.id),
        username: u.username,
        displayName: u.display_name,
        avatarUrl: u.avatar_url || ""
      }))
    });
  } catch (error) {
    console.error("Users:", error);
    res.status(500).json({ error: "Ошибка поиска." });
  }
});

// Список чатов пользователя
app.get("/api/chats", authenticate, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT c.id, c.type, c.title,
        CASE WHEN c.type='direct' THEN (
          SELECT u.display_name
          FROM chat_members cm
          JOIN users u ON u.id=cm.user_id
          WHERE cm.chat_id=c.id AND cm.user_id<>$1
          LIMIT 1
        ) ELSE c.title END AS display_title,
        (SELECT m.text FROM messages m
         WHERE m.chat_id=c.id
         ORDER BY m.id DESC LIMIT 1) AS last_message
       FROM chats c
       JOIN chat_members mine ON mine.chat_id=c.id
       WHERE mine.user_id=$1
       ORDER BY c.created_at DESC`,
      [req.user.id]
    );

    res.json({
      chats: result.rows.map(c => ({
        id: String(c.id),
        type: c.type,
        title: c.display_title || c.title || "Чат",
        lastMessage: c.last_message || ""
      }))
    });
  } catch (error) {
    console.error("Chats:", error);
    res.status(500).json({ error: "Не удалось загрузить чаты." });
  }
});

// Создать личный чат
app.post("/api/chats/direct", authenticate, async (req, res) => {
  const client = await db.connect();

  try {
    const otherId = String(req.body.userId || "");

    if (!/^\d+$/.test(otherId) ||
        otherId === String(req.user.id)) {
      return res.status(400).json({
        error: "Выбери другого пользователя."
      });
    }

    const other = await client.query(
      "SELECT id FROM users WHERE id=$1",
      [otherId]
    );

    if (!other.rowCount) {
      return res.status(404).json({ error: "Пользователь не найден." });
    }

    const existing = await client.query(
      `SELECT c.id FROM chats c
       JOIN chat_members a ON a.chat_id=c.id AND a.user_id=$1
       JOIN chat_members b ON b.chat_id=c.id AND b.user_id=$2
       WHERE c.type='direct'
         AND (SELECT COUNT(*) FROM chat_members x
              WHERE x.chat_id=c.id)=2
       LIMIT 1`,
      [req.user.id, otherId]
    );

    if (existing.rowCount) {
      return res.json({ chatId: String(existing.rows[0].id) });
    }

    await client.query("BEGIN");

    const chat = await client.query(
      "INSERT INTO chats(title, type) VALUES('', 'direct') RETURNING id"
    );

    await client.query(
      `INSERT INTO chat_members(chat_id, user_id)
       VALUES($1, $2), ($1, $3)`,
      [chat.rows[0].id, req.user.id, otherId]
    );

    await client.query("COMMIT");
    res.json({ chatId: String(chat.rows[0].id) });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("Direct chat:", error);
    res.status(500).json({ error: "Не удалось создать чат." });
  } finally {
    client.release();
  }
});

// Создать группу
app.post("/api/chats/group", authenticate, async (req, res) => {
  const client = await db.connect();

  try {
    const title = String(req.body.title || "").trim().slice(0, 80);
    const memberIds = Array.isArray(req.body.userIds)
      ? [...new Set(req.body.userIds.map(String))]
      : [];

    if (!title) {
      return res.status(400).json({ error: "Укажи название группы." });
    }

    if (memberIds.length > 100 ||
        memberIds.some(id => !/^\d+$/.test(id))) {
      return res.status(400).json({ error: "Неверный список участников." });
    }

    await client.query("BEGIN");

    const chat = await client.query(
      "INSERT INTO chats(title, type) VALUES($1, 'group') RETURNING id",
      [title]
    );

    const allIds = [...new Set([
      String(req.user.id), ...memberIds
    ])];

    for (const userId of allIds) {
      const exists = await client.query(
        "SELECT id FROM users WHERE id=$1",
        [userId]
      );

      if (exists.rowCount) {
        await client.query(
          `INSERT INTO chat_members(chat_id,user_id)
           VALUES($1,$2) ON CONFLICT DO NOTHING`,
          [chat.rows[0].id, userId]
        );
      }
    }

    await client.query("COMMIT");
    res.json({ chatId: String(chat.rows[0].id) });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("Group chat:", error);
    res.status(500).json({ error: "Не удалось создать группу." });
  } finally {
    client.release();
  }
});

// История сообщений
app.get("/api/chats/:id/messages", authenticate, async (req, res) => {
  try {
    const chatId = req.params.id;

    if (!/^\d+$/.test(chatId)) {
      return res.status(400).json({ error: "Неверный ID чата." });
    }

    if (!(await isChatMember(chatId, req.user.id))) {
      return res.status(403).json({ error: "Нет доступа к этому чату." });
    }

    const result = await db.query(
      `SELECT id, chat_id, user_id, sender_name, text, created_at
       FROM messages WHERE chat_id=$1
       ORDER BY id DESC LIMIT 100`,
      [chatId]
    );

    res.json({
      messages: result.rows.reverse().map(m => ({
        id: String(m.id),
        chatId: String(m.chat_id),
        userId: m.user_id ? String(m.user_id) : null,
        senderName: m.sender_name,
        text: m.text,
        createdAt: m.created_at
      }))
    });
  } catch (error) {
    console.error("History:", error);
    res.status(500).json({ error: "Не удалось загрузить сообщения." });
  }
});

// Отправить сообщение
app.post("/api/chats/:id/messages", authenticate, async (req, res) => {
  try {
    const chatId = req.params.id;
    const text = String(req.body.text || "").trim();

    if (!/^\d+$/.test(chatId)) {
      return res.status(400).json({ error: "Неверный ID чата." });
    }

    if (!text || text.length > 4000) {
      return res.status(400).json({
        error: "Сообщение должно содержать от 1 до 4000 символов."
      });
    }

    if (!(await isChatMember(chatId, req.user.id))) {
      return res.status(403).json({ error: "Нет доступа к этому чату." });
    }

    const message = await saveMessage(
      chatId,
      req.user.id,
      req.user.display_name,
      text
    );

    res.json({ message });
  } catch (error) {
    console.error("Send message:", error);
    res.status(500).json({ error: "Не удалось отправить сообщение." });
  }
});

// Vilis AI
app.post("/api/ai", authenticate, async (req, res) => {
  try {
    const prompt = String(req.body.message || "").trim();

    if (!prompt || prompt.length > 3000) {
      return res.status(400).json({
        error: "Напиши сообщение до 3000 символов."
      });
    }

    if (!OPENAI_API_KEY) {
      return res.status(503).json({
        error: "Vilis AI пока не настроен. Добавь OPENAI_API_KEY в Render."
      });
    }

    const response = await fetch(
      "https://api.openai.com/v1/chat/completions",
      {
        method: "POST",
        headers: {
          Authorization: "Bearer " + OPENAI_API_KEY,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          model: OPENAI_MODEL,
          messages: [
            {
              role: "system",
              content:
                "Ты Vilis AI, помощник мессенджера Vilis. " +
                "Отвечай дружелюбно, понятно и на языке пользователя."
            },
            { role: "user", content: prompt }
          ],
          max_tokens: 800
        })
      }
    );

    const data = await response.json();

    if (!response.ok) {
      console.error("AI API error:", data);
      return res.status(502).json({
        error: "Сервис Vilis AI не смог ответить."
      });
    }

    res.json({
      answer: data.choices?.[0]?.message?.content ||
        "Ответ не получен."
    });
  } catch (error) {
    console.error("AI:", error);
    res.status(500).json({ error: "Ошибка Vilis AI." });
  }
});

// Подключение чатов к Socket.IO
io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth?.token;

    if (!token || !SECRET) {
      return next(new Error("Необходим вход"));
    }

    const payload = jwt.verify(token, SECRET);
    const result = await db.query(
      "SELECT id FROM users WHERE id=$1",
      [payload.id]
    );

    if (!result.rowCount) {
      return next(new Error("Пользователь не найден"));
    }

    socket.userId = String(result.rows[0].id);
    next();
  } catch {
    next(new Error("Недействительная сессия"));
  }
});

io.on("connection", socket => {
  socket.on("join_chat", async rawChatId => {
    try {
      const chatId = String(rawChatId || "");

      if (!/^\d+$/.test(chatId)) return;

      if (await isChatMember(chatId, socket.userId)) {
        socket.join("chat:" + chatId);
      }
    } catch (error) {
      console.error("Socket join:", error);
    }
  });

  socket.on("leave_chat", rawChatId => {
    const chatId = String(rawChatId || "");
    if (/^\d+$/.test(chatId)) {
      socket.leave("chat:" + chatId);
    }
  });
});

// Telegram-бот
if (TELEGRAM_BOT_TOKEN) {
  try {
    const bot = new TelegramBot(TELEGRAM_BOT_TOKEN, {
      polling: true
    });

    bot.onText(/^\/start(?:\s+(.+))?/, async msg => {
      const code = String(msg.text.split(/\s+/)[1] || "").trim();

      if (code) {
        await linkTelegram(bot, msg, code);
      } else {
        bot.sendMessage(
          msg.chat.id,
          "Привет! Я бот Vilis Messenger.\n\n" +
          "Чтобы связать аккаунт, создай код в настройках Vilis " +
          "и отправь /link КОД"
        );
      }
    });

    bot.onText(/^\/link\s+([A-Za-z0-9]+)$/, async (msg, match) => {
      await linkTelegram(bot, msg, match[1]);
    });

    bot.on("message", async msg => {
      if (!msg.text || msg.text.startsWith("/")) return;

      try {
        const result = await db.query(
          "SELECT id,display_name FROM users WHERE telegram_id=$1",
          [String(msg.from.id)]
        );

        if (!result.rowCount) {
          return bot.sendMessage(
            msg.chat.id,
            "Сначала свяжи аккаунт Vilis командой /link КОД."
          );
        }

        const user = result.rows[0];

        const chat = await db.query(
          "SELECT id FROM chats WHERE type='telegram' AND title=$1 LIMIT 1",
          ["Telegram " + user.id]
        );

        let chatId;

        if (chat.rowCount) {
          chatId = chat.rows[0].id;
        } else {
          const created = await db.query(
            "INSERT INTO chats(title,type) VALUES($1,'telegram') RETURNING id",
            ["Telegram " + user.id]
          );

          chatId = created.rows[0].id;

          await db.query(
            "INSERT INTO chat_members(chat_id,user_id) VALUES($1,$2)",
            [chatId, user.id]
          );
        }

        await saveMessage(
          chatId,
          user.id,
          user.display_name,
          msg.text
        );

        bot.sendMessage(msg.chat.id, "Сообщение сохранено в Vilis.");
      } catch (error) {
        console.error("Telegram message:", error);
        bot.sendMessage(msg.chat.id, "Ошибка обработки сообщения.");
      }
    });

    bot.on("polling_error", error => {
      console.error("Telegram polling:", error.message);
    });

    console.log("Telegram bot is enabled");
  } catch (error) {
    console.error("Telegram bot failed:", error.message);
  }
} else {
  console.log("Telegram bot is disabled: token not configured");
}

async function linkTelegram(bot, msg, code) {
  try {
    const result = await db.query(
      `UPDATE users
       SET telegram_id=$1, link_code=NULL, link_expires=NULL
       WHERE link_code=$2 AND link_expires>NOW()
       RETURNING username`,
      [String(msg.from.id), code]
    );

    if (!result.rowCount) {
      return bot.sendMessage(
        msg.chat.id,
        "Код недействителен или истёк. Создай новый код в Vilis."
      );
    }

    bot.sendMessage(
      msg.chat.id,
      "Аккаунт @" + result.rows[0].username + " связан с Telegram!"
    );
  } catch (error) {
    console.error("Telegram link:", error);
    bot.sendMessage(msg.chat.id, "Не удалось связать аккаунт.");
  }
}

// Создать код для привязки Telegram
app.post("/api/telegram/link-code", authenticate, async (req, res) => {
  try {
    const code = crypto.randomInt(100000, 1000000).toString();

    await db.query(
      `UPDATE users SET link_code=$1,
       link_expires=NOW() + INTERVAL '10 minutes'
       WHERE id=$2`,
      [code, req.user.id]
    );

    res.json({
      code,
      instruction: "Отправь боту /link " + code
    });
  } catch (error) {
    console.error("Telegram code:", error);
    res.status(500).json({ error: "Не удалось создать код." });
  }
});

// Ошибки сервера
app.use((err, req, res, next) => {
  console.error("Server error:", err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: "Внутренняя ошибка сервера." });
});

async function start() {
  if (!DATABASE_URL) {
    throw new Error("Добавь DATABASE_URL в Environment на Render.");
  }

  if (!SECRET) {
    throw new Error("Добавь SESSION_SECRET в Environment на Render.");
  }

  await initDB();

  server.listen(PORT, "0.0.0.0", () => {
    console.log("Vilis Messenger started on port " + PORT);
  });
}

start().catch(error => {
  console.error("Startup failed:", error);
  process.exit(1);
});
const express = require("express");
const path = require("path");
const http = require("http");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const { Server } = require("socket.io");
const TelegramBot = require("node-telegram-bot-api");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;
const SECRET = process.env.SESSION_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const OPENAI_MODEL = process.env.OPENAI_MODEL || "gpt-4o-mini";
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;

app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

const db = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL && /render\.com/i.test(DATABASE_URL)
    ? { rejectUnauthorized: false }
    : undefined
});

async function initDB() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      username VARCHAR(24) UNIQUE NOT NULL,
      display_name VARCHAR(60) NOT NULL,
      password_hash TEXT NOT NULL,
      avatar_url TEXT DEFAULT '',
      telegram_id BIGINT UNIQUE,
      link_code VARCHAR(6),
      link_expires TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS chats (
      id BIGSERIAL PRIMARY KEY,
      title VARCHAR(80) DEFAULT '',
      type VARCHAR(12) NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS chat_members (
      chat_id BIGINT REFERENCES chats(id) ON DELETE CASCADE,
      user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
      PRIMARY KEY (chat_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY,
      chat_id BIGINT REFERENCES chats(id) ON DELETE CASCADE,
      user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
      sender_name VARCHAR(60) NOT NULL,
      text TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS messages_chat_idx
      ON messages(chat_id, id);
  `);

  const general = await db.query(
    "SELECT id FROM chats WHERE type='general' LIMIT 1"
  );

  if (!general.rowCount) {
    await db.query(
      "INSERT INTO chats(title, type) VALUES($1, $2)",
      ["Общий чат", "general"]
    );
  }
}

function tokenFor(user) {
  if (!SECRET) throw new Error("SESSION_SECRET не настроен");

  return jwt.sign(
    { id: String(user.id), username: user.username },
    SECRET,
    { expiresIn: "14d" }
  );
}

function safeUser(user) {
  return {
    id: String(user.id),
    username: user.username,
    displayName: user.display_name,
    avatarUrl: user.avatar_url || "",
    telegramLinked: Boolean(user.telegram_id)
  };
}

async function authenticate(req, res, next) {
  try {
    const token = (req.headers.authorization || "")
      .replace(/^Bearer\s+/i, "");

    if (!token || !SECRET) {
      return res.status(401).json({ error: "Войди в аккаунт." });
    }

    const payload = jwt.verify(token, SECRET);
    const result = await db.query(
      `SELECT id, username, display_name, password_hash,
              avatar_url, telegram_id
       FROM users WHERE id=$1`,
      [payload.id]
    );

    if (!result.rowCount) {
      return res.status(401).json({ error: "Аккаунт не найден." });
    }

    req.user = result.rows[0];
    next();
  } catch {
    return res.status(401).json({
      error: "Сессия завершена. Войди заново."
    });
  }
}

async function isChatMember(chatId, userId) {
  const result = await db.query(
    "SELECT 1 FROM chat_members WHERE chat_id=$1 AND user_id=$2",
    [chatId, userId]
  );
  return result.rowCount > 0;
}

async function saveMessage(chatId, userId, senderName, text) {
  const result = await db.query(
    `INSERT INTO messages(chat_id, user_id, sender_name, text)
     VALUES($1, $2, $3, $4)
     RETURNING id, chat_id, user_id, sender_name, text, created_at`,
    [chatId, userId || null, senderName, String(text).slice(0, 4000)]
  );

  const row = result.rows[0];

  const message = {
    id: String(row.id),
    chatId: String(row.chat_id),
    userId: row.user_id ? String(row.user_id) : null,
    senderName: row.sender_name,
    text: row.text,
    createdAt: row.created_at
  };

  io.to("chat:" + chatId).emit("new_message", message);
  return message;
}

// Проверка сервера
app.get("/health", (req, res) => {
  res.json({ ok: true, app: "Vilis Messenger" });
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Регистрация
app.post("/api/register", async (req, res) => {
  try {
    const username = String(req.body.username || "")
      .trim().toLowerCase();
    const displayName = String(
      req.body.displayName || username
    ).trim().slice(0, 60);
    const password = String(req.body.password || "");

    if (!/^[a-z0-9_]{3,24}$/.test(username)) {
      return res.status(400).json({
        error: "Логин: 3–24 символа, латинские буквы, цифры и _."
      });
    }

    if (password.length < 8 || password.length > 128) {
      return res.status(400).json({
        error: "Пароль должен содержать от 8 до 128 символов."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await db.query(
      `INSERT INTO users(username, display_name, password_hash)
       VALUES($1, $2, $3)
       RETURNING id, username, display_name, avatar_url, telegram_id`,
      [username, displayName || username, passwordHash]
    );

    const user = result.rows[0];

    const general = await db.query(
      "SELECT id FROM chats WHERE type='general' LIMIT 1"
    );

    if (general.rowCount) {
      await db.query(
        `INSERT INTO chat_members(chat_id, user_id)
         VALUES($1, $2) ON CONFLICT DO NOTHING`,
        [general.rows[0].id, user.id]
      );
    }

    res.json({ token: tokenFor(user), user: safeUser(user) });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ error: "Логин уже занят." });
    }

    console.error("Register:", error);
    res.status(500).json({ error: "Не удалось зарегистрироваться." });
  }
});

// Вход
app.post("/api/login", async (req, res) => {
  try {
    const username = String(req.body.username || "")
      .trim().toLowerCase();
    const password = String(req.body.password || "");

    const result = await db.query(
      "SELECT * FROM users WHERE username=$1",
      [username]
    );

    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(
      password, user.password_hash
    ))) {
      return res.status(401).json({
        error: "Неверный логин или пароль."
      });
    }

    res.json({ token: tokenFor(user), user: safeUser(user) });
  } catch (error) {
    console.error("Login:", error);
    res.status(500).json({ error: "Ошибка входа." });
  }
});

// Мой профиль
app.get("/api/me", authenticate, (req, res) => {
  res.json({ user: safeUser(req.user) });
});

app.patch("/api/me", authenticate, async (req, res) => {
  try {
    const name = String(req.body.displayName || "")
      .trim().slice(0, 60);
    const avatar = String(req.body.avatarUrl || "")
      .trim().slice(0, 500);

    if (!name) {
      return res.status(400).json({ error: "Укажи имя профиля." });
    }

    if (avatar && !/^https:\/\//i.test(avatar)) {
      return res.status(400).json({
        error: "Ссылка на аватар должна начинаться с https://"
      });
    }

    const result = await db.query(
      `UPDATE users SET display_name=$1, avatar_url=$2
       WHERE id=$3
       RETURNING id, username, display_name, avatar_url, telegram_id`,
      [name, avatar, req.user.id]
    );

    res.json({ user: safeUser(result.rows[0]) });
  } catch (error) {
    console.error("Profile:", error);
    res.status(500).json({ error: "Не удалось сохранить профиль." });
  }
});

// Поиск пользователей
app.get("/api/users", authenticate, async (req, res) => {
  try {
    const q = String(req.query.q || "").trim().slice(0, 40);

    const result = await db.query(
      `SELECT id, username, display_name, avatar_url
       FROM users
       WHERE id<>$1
         AND ($2='' OR username ILIKE $3 OR display_name ILIKE $3)
       ORDER BY display_name
       LIMIT 50`,
      [req.user.id, q, "%" + q + "%"]
    );

    res.json({
      users: result.rows.map(u => ({
        id: String(u.id),
        username: u.username,
        displayName: u.display_name,
        avatarUrl: u.avatar_url || ""
      }))
    });
  } catch (error) {
    console.error("Users:", error);
    res.status(500).json({ error: "Ошибка поиска." });
  }
});

// Список чатов пользователя
app.get("/api/chats", authenticate, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT c.id, c.type, c.title,
        CASE WHEN c.type='direct' THEN (
          SELECT u.display_name
          FROM chat_members cm
          JOIN users u ON u.id=cm.user_id
          WHERE cm.chat_id=c.id AND cm.user_id<>$1
          LIMIT 1
        ) ELSE c.title END AS display_title,
        (SELECT m.text FROM messages m
         WHERE m.chat_id=c.id
         ORDER BY m.id DESC LIMIT 1) AS last_message
       FROM chats c
       JOIN chat_members mine ON mine.chat_id=c.id
       WHERE mine.user_id=$1
       ORDER BY c.created_at DESC`,
      [req.user.id]
    );

    res.json({
      chats: result.rows.map(c => ({
        id: String(c.id),
        type: c.type,
        title: c.display_title || c.title || "Чат",
        lastMessage: c.last_message || ""
      }))
    });
  } catch (error) {
    console.error("Chats:", error);
    res.status(500).json({ error: "Не удалось загрузить чаты." });
  }
});

// Создать личный чат
app.post("/api/chats/direct", authenticate, async (req, res) => {
  const client = await db.connect();

  try {
    const otherId = String(req.body.userId || "");

    if (!/^\d+$/.test(otherId) ||
        otherId === String(req.user.id)) {
      return res.status(400).json({
        error: "Выбери другого пользователя."
      });
    }

    const other = await client.query(
      "SELECT id FROM users WHERE id=$1",
      [otherId]
    );

    if (!other.rowCount) {
      return res.status(404).json({ error: "Пользователь не найден." });
    }

    const existing = await client.query(
      `SELECT c.id FROM chats c
       JOIN chat_members a ON a.chat_id=c.id AND a.user_id=$1
       JOIN chat_members b ON b.chat_id=c.id AND b.user_id=$2
       WHERE c.type='direct'
         AND (SELECT COUNT(*) FROM chat_members x
              WHERE x.chat_id=c.id)=2
       LIMIT 1`,
      [req.user.id, otherId]
    );

    if (existing.rowCount) {
      return res.json({ chatId: String(existing.rows[0].id) });
    }

    await client.query("BEGIN");

    const chat = await client.query(
      "INSERT INTO chats(title, type) VALUES('', 'direct') RETURNING id"
    );

    await client.query(
      `INSERT INTO chat_members(chat_id, user_id)
       VALUES($1, $2), ($1, $3)`,
      [chat.rows[0].id, req.user.id, otherId]
    );

    await client.query("COMMIT");
    res.json({ chatId: String(chat.rows[0].id) });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("Direct chat:", error);
    res.status(500).json({ error: "Не удалось создать чат." });
  } finally {
    client.release();
  }
});

// Создать группу
app.post("/api/chats/group", authenticate, async (req, res) => {
  const client = await db.connect();

  try {
    const title = String(req.body.title || "").trim().slice(0, 80);
    const memberIds = Array.isArray(req.body.userIds)
      ? [...new Set(req.body.userIds.map(String))]
      : [];

    if (!title) {
      return res.status(400).json({ error: "Укажи название группы." });
    }

    if (memberIds.length > 100 ||
        memberIds.some(id => !/^\d+$/.test(id))) {
      return res.status(400).json({ error: "Неверный список участников." });
    }

    await client.query("BEGIN");

    const chat = await client.query(
      "INSERT INTO chats(title, type) VALUES($1, 'group') RETURNING id",
      [title]
    );

    const allIds = [...new Set([
      String(req.user.id), ...memberIds
    ])];

    for (const userId of allIds) {
      const exists = await client.query(
        "SELECT id FROM users WHERE id=$1",
        [userId]
      );

      if (exists.rowCount) {
        await client.query(
          `INSERT INTO chat_members(chat_id,user_id)
           VALUES($1,$2) ON CONFLICT DO NOTHING`,
          [chat.rows[0].id, userId]
        );
      }
    }

    await client.query("COMMIT");
    res.json({ chatId: String(chat.rows[0].id) });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("Group chat:", error);
    res.status(500).json({ error: "Не удалось создать группу." });
  } finally {
    client.release();
  }
});

// История сообщений
app.get("/api/chats/:id/messages", authenticate, async (req, res) => {
  try {
    const chatId = req.params.id;

    if (!/^\d+$/.test(chatId)) {
      return res.status(400).json({ error: "Неверный ID чата." });
    }

    if (!(await isChatMember(chatId, req.user.id))) {
      return res.status(403).json({ error: "Нет доступа к этому чату." });
    }

    const result = await db.query(
      `SELECT id, chat_id, user_id, sender_name, text, created_at
       FROM messages WHERE chat_id=$1
       ORDER BY id DESC LIMIT 100`,
      [chatId]
    );

    res.json({
      messages: result.rows.reverse().map(m => ({
        id: String(m.id),
        chatId: String(m.chat_id),
        userId: m.user_id ? String(m.user_id) : null,
        senderName: m.sender_name,
        text: m.text,
        createdAt: m.created_at
      }))
    });
  } catch (error) {
    console.error("History:", error);
    res.status(500).json({ error: "Не удалось загрузить сообщения." });
  }
});

// Отправить сообщение
app.post("/api/chats/:id/messages", authenticate, async (req, res) => {
  try {
    const chatId = req.params.id;
    const text = String(req.body.text || "").trim();

    if (!/^\d+$/.test(chatId)) {
      return res.status(400).json({ error: "Неверный ID чата." });
    }

    if (!text || text.length > 4000) {
      return res.status(400).json({
        error: "Сообщение должно содержать от 1 до 4000 символов."
      });
    }

    if (!(await isChatMember(chatId, req.user.id))) {
      return res.status(403).json({ error: "Нет доступа к этому чату." });
    }

    const message = await saveMessage(
      chatId,
      req.user.id,
      req.user.display_name,
      text
    );

    res.json({ message });
  } catch (error) {
    console.error("Send message:", error);
    res.status(500).json({ error: "Не удалось отправить сообщение." });
  }
});

// Vilis AI
app.post("/api/ai", authenticate, async (req, res) => {
  try {
    const prompt = String(req.body.message || "").trim();

    if (!prompt || prompt.length > 3000) {
      return res.status(400).json({
        error: "Напиши сообщение до 3000 символов."
      });
    }

    if (!OPENAI_API_KEY) {
      return res.status(503).json({
        error: "Vilis AI пока не настроен. Добавь OPENAI_API_KEY в Render."
      });
    }

    const response = await fetch(
      "https://api.openai.com/v1/chat/completions",
      {
        method: "POST",
        headers: {
          Authorization: "Bearer " + OPENAI_API_KEY,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          model: OPENAI_MODEL,
          messages: [
            {
              role: "system",
              content:
                "Ты Vilis AI, помощник мессенджера Vilis. " +
                "Отвечай дружелюбно, понятно и на языке пользователя."
            },
            { role: "user", content: prompt }
          ],
          max_tokens: 800
        })
      }
    );

    const data = await response.json();

    if (!response.ok) {
      console.error("AI API error:", data);
      return res.status(502).json({
        error: "Сервис Vilis AI не смог ответить."
      });
    }

    res.json({
      answer: data.choices?.[0]?.message?.content ||
        "Ответ не получен."
    });
  } catch (error) {
    console.error("AI:", error);
    res.status(500).json({ error: "Ошибка Vilis AI." });
  }
});

// Подключение чатов к Socket.IO
io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth?.token;

    if (!token || !SECRET) {
      return next(new Error("Необходим вход"));
    }

    const payload = jwt.verify(token, SECRET);
    const result = await db.query(
      "SELECT id FROM users WHERE id=$1",
      [payload.id]
    );

    if (!result.rowCount) {
      return next(new Error("Пользователь не найден"));
    }

    socket.userId = String(result.rows[0].id);
    next();
  } catch {
    next(new Error("Недействительная сессия"));
  }
});

io.on("connection", socket => {
  socket.on("join_chat", async rawChatId => {
    try {
      const chatId = String(rawChatId || "");

      if (!/^\d+$/.test(chatId)) return;

      if (await isChatMember(chatId, socket.userId)) {
        socket.join("chat:" + chatId);
      }
    } catch (error) {
      console.error("Socket join:", error);
    }
  });

  socket.on("leave_chat", rawChatId => {
    const chatId = String(rawChatId || "");
    if (/^\d+$/.test(chatId)) {
      socket.leave("chat:" + chatId);
    }
  });
});

// Telegram-бот
if (TELEGRAM_BOT_TOKEN) {
  try {
    const bot = new TelegramBot(TELEGRAM_BOT_TOKEN, {
      polling: true
    });

    bot.onText(/^\/start(?:\s+(.+))?/, async msg => {
      const code = String(msg.text.split(/\s+/)[1] || "").trim();

      if (code) {
        await linkTelegram(bot, msg, code);
      } else {
        bot.sendMessage(
          msg.chat.id,
          "Привет! Я бот Vilis Messenger.\n\n" +
          "Чтобы связать аккаунт, создай код в настройках Vilis " +
          "и отправь /link КОД"
        );
      }
    });

    bot.onText(/^\/link\s+([A-Za-z0-9]+)$/, async (msg, match) => {
      await linkTelegram(bot, msg, match[1]);
    });

    bot.on("message", async msg => {
      if (!msg.text || msg.text.startsWith("/")) return;

      try {
        const result = await db.query(
          "SELECT id,display_name FROM users WHERE telegram_id=$1",
          [String(msg.from.id)]
        );

        if (!result.rowCount) {
          return bot.sendMessage(
            msg.chat.id,
            "Сначала свяжи аккаунт Vilis командой /link КОД."
          );
        }

        const user = result.rows[0];

        const chat = await db.query(
          "SELECT id FROM chats WHERE type='telegram' AND title=$1 LIMIT 1",
          ["Telegram " + user.id]
        );

        let chatId;

        if (chat.rowCount) {
          chatId = chat.rows[0].id;
        } else {
          const created = await db.query(
            "INSERT INTO chats(title,type) VALUES($1,'telegram') RETURNING id",
            ["Telegram " + user.id]
          );

          chatId = created.rows[0].id;

          await db.query(
            "INSERT INTO chat_members(chat_id,user_id) VALUES($1,$2)",
            [chatId, user.id]
          );
        }

        await saveMessage(
          chatId,
          user.id,
          user.display_name,
          msg.text
        );

        bot.sendMessage(msg.chat.id, "Сообщение сохранено в Vilis.");
      } catch (error) {
        console.error("Telegram message:", error);
        bot.sendMessage(msg.chat.id, "Ошибка обработки сообщения.");
      }
    });

    bot.on("polling_error", error => {
      console.error("Telegram polling:", error.message);
    });

    console.log("Telegram bot is enabled");
  } catch (error) {
    console.error("Telegram bot failed:", error.message);
  }
} else {
  console.log("Telegram bot is disabled: token not configured");
}

async function linkTelegram(bot, msg, code) {
  try {
    const result = await db.query(
      `UPDATE users
       SET telegram_id=$1, link_code=NULL, link_expires=NULL
       WHERE link_code=$2 AND link_expires>NOW()
       RETURNING username`,
      [String(msg.from.id), code]
    );

    if (!result.rowCount) {
      return bot.sendMessage(
        msg.chat.id,
        "Код недействителен или истёк. Создай новый код в Vilis."
      );
    }

    bot.sendMessage(
      msg.chat.id,
      "Аккаунт @" + result.rows[0].username + " связан с Telegram!"
    );
  } catch (error) {
    console.error("Telegram link:", error);
    bot.sendMessage(msg.chat.id, "Не удалось связать аккаунт.");
  }
}

// Создать код для привязки Telegram
app.post("/api/telegram/link-code", authenticate, async (req, res) => {
  try {
    const code = crypto.randomInt(100000, 1000000).toString();

    await db.query(
      `UPDATE users SET link_code=$1,
       link_expires=NOW() + INTERVAL '10 minutes'
       WHERE id=$2`,
      [code, req.user.id]
    );

    res.json({
      code,
      instruction: "Отправь боту /link " + code
    });
  } catch (error) {
    console.error("Telegram code:", error);
    res.status(500).json({ error: "Не удалось создать код." });
  }
});

// Ошибки сервера
app.use((err, req, res, next) => {
  console.error("Server error:", err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: "Внутренняя ошибка сервера." });
});

async function start() {
  if (!DATABASE_URL) {
    throw new Error("Добавь DATABASE_URL в Environment на Render.");
  }

  if (!SECRET) {
    throw new Error("Добавь SESSION_SECRET в Environment на Render.");
  }

  await initDB();

  server.listen(PORT, "0.0.0.0", () => {
    console.log("Vilis Messenger started on port " + PORT);
  });
}

start().catch(error => {
  console.error("Startup failed:", error);
  process.exit(1);
});
