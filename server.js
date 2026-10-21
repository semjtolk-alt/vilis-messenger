const http = require("http");
const PORT = process.env.PORT || 3000;
const TOKEN = process.env.TELEGRAM_BOT_TOKEN;

const server = http.createServer(async (req, res) => {
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Access-Control-Allow-Origin", "null");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    return res.end();
  }

  if (req.url === "/health") {
    res.writeHead(200);
    return res.end(JSON.stringify({
      status: "ok",
      app: "Vilis"
    }));
  }

  res.writeHead(404);
  res.end(JSON.stringify({
    error: "Not found"
  }));
});

server.listen(PORT, "0.0.0.0", () => {
  console.log("Vilis server started on port " + PORT);
  console.log("Telegram configured: " + Boolean(TOKEN));
});
