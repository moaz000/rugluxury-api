import { config } from "../config"

export async function sendTelegramNotification(data: {
  name: string
  phone?: string
  email?: string
  product?: string
  message: string
  ip?: string
  type: "contact" | "order" | "booking" | "quote"
}) {
  if (!config.telegramBotToken || !config.telegramChatId) return

  const text = [
    `📩 *New ${data.type.toUpperCase()}*`,
    `━━━━━━━━━━━━━━━`,
    `👤 *Name:* ${data.name}`,
    data.phone ? `📞 *Phone:* ${data.phone}` : "",
    data.email ? `📧 *Email:* ${data.email}` : "",
    data.product ? `🛒 *Product:* ${data.product}` : "",
    `📝 *Message:* ${data.message}`,
    data.ip ? `🌐 *IP:* ${data.ip}` : "",
    `🕐 *Time:* ${new Date().toLocaleString()}`,
    ``,
    `[💬 Open WhatsApp](https://wa.me/${data.phone?.replace(/[^0-9]/g, "") || ""})`,
    `📊 [View Dashboard](${config.corsOrigin}/admin)`,
  ]
    .filter(Boolean)
    .join("\n")

  try {
    await fetch(`https://api.telegram.org/bot${config.telegramBotToken}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: config.telegramChatId,
        text,
        parse_mode: "Markdown",
        disable_web_page_preview: true,
      }),
    })
  } catch (e) {
    console.error("Telegram notification failed:", e)
  }
}
