import express from "express"
import cors from "cors"
import helmet from "helmet"
import morgan from "morgan"
import cookieParser from "cookie-parser"
import rateLimit from "express-rate-limit"
import path from "path"
import jwt from "jsonwebtoken"
import bcrypt from "bcryptjs"
import { config } from "./config"
import { prisma } from "./prisma"
import { authenticate, authorize, type AuthRequest } from "./middleware/auth"
import { sendTelegramNotification } from "./utils/telegram"
import { logActivity } from "./utils/logger"
import type { Request } from "express"

function q(req: Request, key: string): string | undefined {
  const v = req.query[key]
  return typeof v === "string" ? v : undefined
}
function pid(req: Request): string { return (req.params as any).id || "" }

const app = express()

// Middleware
app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }))
app.use(cors({ origin: config.corsOrigin, credentials: true }))
app.set("trust proxy", config.isProduction ? 1 : 0)
app.use(morgan("dev"))
app.use(express.json({ limit: "50mb" }))
app.use(cookieParser())
app.use("/uploads", express.static(path.join(process.cwd(), "uploads")))

const limiter = rateLimit({ windowMs: 60 * 1000, max: 100 })
app.use("/api/", limiter)

// ─── Health Check ─────────────────────────────────────
app.get("/health", (_req, res) => res.json({ status: "ok", timestamp: new Date().toISOString() }))

// ─── Auth ─────────────────────────────────────────────
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body
    const user = await prisma.user.findUnique({ where: { email } })
    if (!user) return res.status(401).json({ error: "Invalid email or password" })

    const valid = await bcrypt.compare(password, user.password)
    if (!valid) return res.status(401).json({ error: "Invalid email or password" })
    if (!user.active) return res.status(403).json({ error: "Account is deactivated" })

    const token = jwt.sign(
      { id: user.id, role: user.role, name: user.name, email: user.email },
      config.jwtSecret,
      { expiresIn: config.jwtExpiresIn } as any
    )

    await prisma.loginLog.create({ data: { userId: user.id, ip: req.ip, success: true } })
    await logActivity({ userId: user.id, action: "login", entity: "user", entityId: user.id, ip: req.ip })

    res.cookie("token", token, { httpOnly: true, secure: config.isProduction, sameSite: "lax", maxAge: 7 * 24 * 60 * 60 * 1000 })
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role, avatar: user.avatar } })
  } catch (e) {
    res.status(500).json({ error: "Login failed" })
  }
})

app.post("/api/auth/logout", (_req, res) => {
  res.clearCookie("token")
  res.json({ ok: true })
})

app.get("/api/auth/me", authenticate, (req: AuthRequest, res) => {
  res.json(req.user)
})

app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body
    if (!name || !email || !password) return res.status(400).json({ error: "Name, email, and password are required" })
    if (password.length < 6) return res.status(400).json({ error: "Password must be at least 6 characters" })

    const existing = await prisma.user.findUnique({ where: { email } })
    if (existing) return res.status(400).json({ error: "Email already registered" })

    const hashed = await bcrypt.hash(password, 12)
    const user = await prisma.user.create({ data: { name, email, password: hashed, role: "client", active: true } })

    const token = jwt.sign(
      { id: user.id, role: user.role, name: user.name, email: user.email },
      config.jwtSecret,
      { expiresIn: config.jwtExpiresIn } as any
    )

    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } })
  } catch (e: any) {
    res.status(400).json({ error: e.message || "Registration failed" })
  }
})

// ─── Users ────────────────────────────────────────────
app.get("/api/users", authenticate, authorize("admin"), async (_req, res) => {
  const users = await prisma.user.findMany({ select: { id: true, name: true, email: true, role: true, active: true, phone: true, createdAt: true } })
  res.json(users)
})

app.post("/api/users", authenticate, authorize("admin"), async (req: AuthRequest, res) => {
  try {
    const hashed = await bcrypt.hash(req.body.password, 12)
    const user = await prisma.user.create({ data: { ...req.body, password: hashed } })
    await logActivity({ userId: req.user?.id, action: "create", entity: "user", entityId: user.id, ip: req.ip })
    res.status(201).json({ id: user.id, name: user.name, email: user.email, role: user.role })
  } catch (e: any) {
    res.status(400).json({ error: e.message })
  }
})

app.put("/api/users/:id", authenticate, authorize("admin"), async (req: AuthRequest, res) => {
  const id = pid(req)
  const data: any = { ...req.body }
  if (data.password) {
    data.password = await bcrypt.hash(data.password, 12)
  } else delete data.password
  const user = await prisma.user.update({ where: { id }, data })
  await logActivity({ userId: req.user?.id, action: "update", entity: "user", entityId: user.id, ip: req.ip })
  res.json({ id: user.id, name: user.name, email: user.email, role: user.role })
})

app.delete("/api/users/:id", authenticate, authorize("admin"), async (req: AuthRequest, res) => {
  const id = pid(req)
  await prisma.user.delete({ where: { id } })
  await logActivity({ userId: req.user?.id, action: "delete", entity: "user", entityId: id, ip: req.ip })
  res.json({ ok: true })
})

// ─── Dashboard ────────────────────────────────────────
app.get("/api/dashboard", authenticate, async (_req, res) => {
  const [products, orders, customers, messages, visitors] = await Promise.all([
    prisma.product.count(),
    prisma.order.count(),
    prisma.customer.count(),
    prisma.message.count(),
    prisma.analyticsEvent.count({ where: { type: "visitor", createdAt: { gte: new Date(Date.now() - 86400000) } } }),
  ])
  const sales = await prisma.order.aggregate({ _sum: { total: true }, where: { status: { not: "cancelled" } } })
  const recentOrders = await prisma.order.findMany({ take: 5, orderBy: { createdAt: "desc" }, include: { items: true } })
  const lowStock = await prisma.product.findMany({ where: { inStock: true }, take: 5, orderBy: { createdAt: "asc" } })

  res.json({ stats: { products, orders, customers, messages, visitors, sales: sales._sum.total || 0 }, recentOrders, lowStock })
})

// ─── Products ─────────────────────────────────────────
app.get("/api/products", async (req, res) => {
  const category = q(req, "category")
  const search = q(req, "search")
  const page = q(req, "page") || "1"
  const limit = q(req, "limit") || "50"
  const where: any = {}
  if (category) where.categoryId = category
  if (search) where.OR = [{ name: { contains: search } }, { sku: { contains: search } }]
  const items = await prisma.product.findMany({ where, include: { images: { orderBy: { sortOrder: "asc" } }, category: true }, orderBy: { createdAt: "desc" }, skip: (Number(page) - 1) * Number(limit), take: Number(limit) })
  const total = await prisma.product.count({ where })
  res.json({ items, total, page: Number(page), totalPages: Math.ceil(total / Number(limit)) })
})

app.get("/api/products/:id", async (req, res) => {
  const product = await prisma.product.findUnique({ where: { id: pid(req) }, include: { images: { orderBy: { sortOrder: "asc" } }, category: true } })
  if (!product) return res.status(404).json({ error: "Product not found" })
  res.json(product)
})

app.post("/api/products", authenticate, async (req: AuthRequest, res) => {
  const { images, colors, sizes, features, ...data } = req.body
  const product = await prisma.product.create({
    data: {
      ...data,
      colors: JSON.stringify(colors || []),
      sizes: JSON.stringify(sizes || []),
      features: features ? JSON.stringify(features) : null,
      images: { create: (images || []).map((url: string, i: number) => ({ url, sortOrder: i, isFeatured: i === 0 })) },
    },
    include: { images: true },
  })
  await logActivity({ userId: req.user?.id, action: "create", entity: "product", entityId: product.id, ip: req.ip })
  res.status(201).json(product)
})

app.put("/api/products/:id", authenticate, async (req: AuthRequest, res) => {
  const id = pid(req)
  const { images, colors, sizes, features, ...data } = req.body
  if (images) {
    await prisma.productImage.deleteMany({ where: { productId: id } })
    await prisma.productImage.createMany({ data: images.map((url: string, i: number) => ({ productId: id, url, sortOrder: i, isFeatured: i === 0 })) })
  }
  const product = await prisma.product.update({
    where: { id },
    data: {
      ...data,
      colors: colors ? JSON.stringify(colors) : undefined,
      sizes: sizes ? JSON.stringify(sizes) : undefined,
      features: features ? JSON.stringify(features) : undefined,
    },
    include: { images: true },
  })
  await logActivity({ userId: req.user?.id, action: "update", entity: "product", entityId: product.id, ip: req.ip })
  res.json(product)
})

app.delete("/api/products/:id", authenticate, async (req: AuthRequest, res) => {
  const id = pid(req)
  await prisma.product.delete({ where: { id } })
  await logActivity({ userId: req.user?.id, action: "delete", entity: "product", entityId: id, ip: req.ip })
  res.json({ ok: true })
})

// ─── Categories ───────────────────────────────────────
app.get("/api/categories", async (_req, res) => {
  const items = await prisma.category.findMany({ include: { _count: { select: { products: true } } }, orderBy: { sortOrder: "asc" } })
  res.json(items)
})

app.post("/api/categories", authenticate, async (req: AuthRequest, res) => {
  const cat = await prisma.category.create({ data: req.body })
  await logActivity({ userId: req.user?.id, action: "create", entity: "category", entityId: cat.id, ip: req.ip })
  res.status(201).json(cat)
})

app.put("/api/categories/:id", authenticate, async (req: AuthRequest, res) => {
  const id = pid(req)
  const cat = await prisma.category.update({ where: { id }, data: req.body })
  await logActivity({ userId: req.user?.id, action: "update", entity: "category", entityId: cat.id, ip: req.ip })
  res.json(cat)
})

app.delete("/api/categories/:id", authenticate, async (req: AuthRequest, res) => {
  const id = pid(req)
  await prisma.category.delete({ where: { id } })
  await logActivity({ userId: req.user?.id, action: "delete", entity: "category", entityId: id, ip: req.ip })
  res.json({ ok: true })
})

// ─── Orders ───────────────────────────────────────────
app.get("/api/orders", authenticate, async (req, res) => {
  const status = q(req, "status")
  const search = q(req, "search")
  const page = q(req, "page") || "1"
  const limit = q(req, "limit") || "50"
  const where: any = {}
  if (status) where.status = status
  if (search) where.OR = [{ customerName: { contains: search } }, { orderNumber: { contains: search } }]
  const items = await prisma.order.findMany({ where, include: { items: true, customer: true }, orderBy: { createdAt: "desc" }, skip: (Number(page) - 1) * Number(limit), take: Number(limit) })
  const total = await prisma.order.count({ where })
  res.json({ items, total, page: Number(page), totalPages: Math.ceil(total / Number(limit)) })
})

app.get("/api/orders/:id", authenticate, async (req, res) => {
  const order = await prisma.order.findUnique({ where: { id: pid(req) }, include: { items: true, customer: true } })
  if (!order) return res.status(404).json({ error: "Order not found" })
  res.json(order)
})

app.put("/api/orders/:id/status", authenticate, async (req: AuthRequest, res) => {
  const id = pid(req)
  const order = await prisma.order.update({ where: { id }, data: { status: req.body.status } })
  await logActivity({ userId: req.user?.id, action: "update", entity: "order", entityId: order.id, details: { status: req.body.status }, ip: req.ip })
  res.json(order)
})

app.delete("/api/orders/:id", authenticate, authorize("admin"), async (req: AuthRequest, res) => {
  await prisma.order.delete({ where: { id: pid(req) } })
  res.json({ ok: true })
})

// ─── Customers ────────────────────────────────────────
app.get("/api/customers", authenticate, async (req, res) => {
  const search = q(req, "search")
  const page = q(req, "page") || "1"
  const limit = q(req, "limit") || "50"
  const where: any = {}
  if (search) where.OR = [{ name: { contains: search } }, { email: { contains: search } }, { phone: { contains: search } }]
  const items = await prisma.customer.findMany({ where, include: { _count: { select: { orders: true } } }, orderBy: { createdAt: "desc" }, skip: (Number(page) - 1) * Number(limit), take: Number(limit) })
  const total = await prisma.customer.count({ where })
  res.json({ items, total, page: Number(page), totalPages: Math.ceil(total / Number(limit)) })
})

app.post("/api/customers", authenticate, async (req: AuthRequest, res) => {
  const customer = await prisma.customer.create({ data: req.body })
  await logActivity({ userId: req.user?.id, action: "create", entity: "customer", entityId: customer.id, ip: req.ip })
  res.status(201).json(customer)
})

app.put("/api/customers/:id", authenticate, async (req: AuthRequest, res) => {
  const customer = await prisma.customer.update({ where: { id: pid(req) }, data: req.body })
  res.json(customer)
})

app.delete("/api/customers/:id", authenticate, async (req: AuthRequest, res) => {
  await prisma.customer.delete({ where: { id: pid(req) } })
  res.json({ ok: true })
})

// ─── Messages ─────────────────────────────────────────
app.get("/api/messages", authenticate, async (req, res) => {
  const read = q(req, "read")
  const search = q(req, "search")
  const page = q(req, "page") || "1"
  const limit = q(req, "limit") || "50"
  const where: any = {}
  if (read !== undefined) where.read = read === "true"
  if (search) where.OR = [{ name: { contains: search } }, { email: { contains: search } }, { message: { contains: search } }]
  const items = await prisma.message.findMany({ where, orderBy: { createdAt: "desc" }, skip: (Number(page) - 1) * Number(limit), take: Number(limit) })
  const total = await prisma.message.count({ where })
  res.json({ items, total, page: Number(page), totalPages: Math.ceil(total / Number(limit)) })
})

app.put("/api/messages/:id/read", authenticate, async (req, res) => {
  const msg = await prisma.message.update({ where: { id: pid(req) }, data: { read: true } })
  res.json(msg)
})

app.delete("/api/messages/:id", authenticate, async (req, res) => {
  await prisma.message.delete({ where: { id: pid(req) } })
  res.json({ ok: true })
})

// Public: contact form
app.post("/api/contact", async (req, res) => {
  const msg = await prisma.message.create({ data: req.body })
  sendTelegramNotification({ name: req.body.name, phone: req.body.phone, email: req.body.email, message: req.body.message, ip: req.ip, type: "contact" })
  res.status(201).json({ ok: true })
})

// ─── Settings ─────────────────────────────────────────
app.get("/api/settings", async (_req, res) => {
  const settings = await prisma.setting.findMany()
  const obj: Record<string, string> = {}
  settings.forEach((s) => { obj[s.key] = s.value })
  res.json(obj)
})

app.put("/api/settings", authenticate, async (req: AuthRequest, res) => {
  const entries = Object.entries(req.body)
  for (const [key, value] of entries) {
    await prisma.setting.upsert({ where: { key }, update: { value: String(value) }, create: { key, value: String(value) } })
  }
  await logActivity({ userId: req.user?.id, action: "update", entity: "setting", ip: req.ip })
  res.json({ ok: true })
})

// ─── CMS: Site Sections ───────────────────────────────
app.get("/api/content/:page", async (req, res) => {
  const sections = await prisma.siteSection.findMany({ where: { page: (req.params as any).page } })
  const obj: Record<string, any> = {}
  sections.forEach((s: any) => { obj[s.section] = JSON.parse(s.content) })
  res.json(obj)
})

app.put("/api/content/:page/:section", authenticate, async (req: AuthRequest, res) => {
  const p = (req.params as any).page
  const s = (req.params as any).section
  const section = await prisma.siteSection.upsert({
    where: { id: `${p}-${s}` },
    update: { content: JSON.stringify(req.body) },
    create: { id: `${p}-${s}`, page: p, section: s, content: JSON.stringify(req.body) },
  })
  await logActivity({ userId: req.user?.id, action: "update", entity: "content", entityId: section.id, ip: req.ip })
  res.json(section)
})

// ─── Media ────────────────────────────────────────────
import multer from "multer"
import fs from "fs"

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, config.uploadDir),
  filename: (_req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`),
})
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024 } })

app.get("/api/media", authenticate, async (req, res) => {
  const folder = q(req, "folder")
  const page = q(req, "page") || "1"
  const limit = q(req, "limit") || "50"
  const where: any = {}
  if (folder) where.folder = folder
  const items = await prisma.media.findMany({ where, orderBy: { createdAt: "desc" }, skip: (Number(page) - 1) * Number(limit), take: Number(limit) })
  const total = await prisma.media.count({ where })
  res.json({ items, total })
})

app.post("/api/media/upload", authenticate, upload.array("files", 20), async (req: AuthRequest, res) => {
  const files = req.files as Express.Multer.File[]
  if (!files || files.length === 0) return res.status(400).json({ error: "No files uploaded" })

  const results = []
  for (const file of files) {
    const media = await prisma.media.create({
      data: {
        url: `/uploads/${file.filename}`,
        filename: file.originalname,
        mimeType: file.mimetype,
        size: file.size,
        folder: (req.body.folder as string) || "general",
      },
    })
    results.push(media)
  }
  res.status(201).json(results)
})

app.delete("/api/media/:id", authenticate, async (req: AuthRequest, res) => {
  const id = pid(req)
  const media = await prisma.media.findUnique({ where: { id } })
  if (media) {
    const filePath = path.join(process.cwd(), media.url)
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath)
    await prisma.media.delete({ where: { id } })
  }
  res.json({ ok: true })
})

// ─── Telegram Config ──────────────────────────────────
app.post("/api/telegram/test", authenticate, async (req, res) => {
  const { botToken, chatId } = req.body
  try {
    const r = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: chatId, text: "✅ RugLuxury Bot is connected!", parse_mode: "Markdown" }),
    })
    const data: any = await r.json()
    res.json(data.ok ? { ok: true } : { error: data.description })
  } catch {
    res.status(400).json({ error: "Failed to connect" })
  }
})

// ─── Analytics ────────────────────────────────────────
app.post("/api/analytics/track", (req: any, res) => {
  prisma.analyticsEvent.create({ data: { ...req.body, ip: req.ip } }).catch(() => {})
  res.json({ ok: true })
})

app.get("/api/analytics", authenticate, async (req, res) => {
  const from = q(req, "from")
  const to = q(req, "to")
  const type = q(req, "type")
  const where: any = {}
  if (from) where.createdAt = { gte: new Date(from) }
  if (to) where.createdAt = { ...where.createdAt, lte: new Date(to) }
  if (type) where.type = type

  const [totalVisitors, totalPageViews, byPage, byCountry, byReferrer] = await Promise.all([
    prisma.analyticsEvent.count({ where: { ...where, type: "visitor" } }),
    prisma.analyticsEvent.count({ where: { ...where, type: "pageview" } }),
    prisma.analyticsEvent.groupBy({ by: ["page"], where: { ...where, type: "pageview" }, _count: true, orderBy: { _count: { page: "desc" } }, take: 10 }),
    prisma.analyticsEvent.groupBy({ by: ["country"], where, _count: true, orderBy: { _count: { country: "desc" } }, take: 10 }),
    prisma.analyticsEvent.groupBy({ by: ["referrer"], where, _count: true, orderBy: { _count: { referrer: "desc" } }, take: 10 }),
  ])
  res.json({ totalVisitors, totalPageViews, byPage: byPage.filter((p: any) => p.page), byCountry: byCountry.filter((c: any) => c.country), byReferrer: byReferrer.filter((r: any) => r.referrer) })
})

// ─── SEO ──────────────────────────────────────────────
app.get("/api/seo/robots.txt", async (_req, res) => {
  const setting = await prisma.setting.findUnique({ where: { key: "robots_txt" } })
  res.type("text/plain").send(setting?.value || "User-agent: *\nAllow: /\nSitemap: /api/seo/sitemap.xml")
})

app.get("/api/seo/sitemap.xml", async (_req, res) => {
  const products = await prisma.product.findMany({ select: { slug: true, updatedAt: true }, where: { available: true } })
  const categories = await prisma.category.findMany({ select: { slug: true, updatedAt: true } })

  const urls = [
    `<url><loc>${config.corsOrigin}/</loc><priority>1.0</priority></url>`,
    `<url><loc>${config.corsOrigin}/products</loc><priority>0.9</priority></url>`,
    `<url><loc>${config.corsOrigin}/about</loc><priority>0.7</priority></url>`,
    ...products.map((p: any) => `<url><loc>${config.corsOrigin}/products/${p.slug}</loc><lastmod>${p.updatedAt.toISOString()}</lastmod><priority>0.8</priority></url>`),
    ...categories.map((c: any) => `<url><loc>${config.corsOrigin}/collections/${c.slug}</loc><lastmod>${c.updatedAt.toISOString()}</lastmod><priority>0.7</priority></url>`),
  ]

  res.header("Content-Type", "application/xml").send(`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${urls.join("")}</urlset>`)
})

// ─── Backup ──────────────────────────────────────────
app.post("/api/backup", authenticate, authorize("admin"), async (req: AuthRequest, res) => {
  const backupDir = path.join(process.cwd(), "backups")
  if (!fs.existsSync(backupDir)) fs.mkdirSync(backupDir, { recursive: true })

  const filename = `backup-${Date.now()}.json`
  const allData = {
    products: await prisma.product.findMany({ include: { images: true } }),
    categories: await prisma.category.findMany(),
    orders: await prisma.order.findMany({ include: { items: true } }),
    customers: await prisma.customer.findMany(),
    messages: await prisma.message.findMany(),
    settings: await prisma.setting.findMany(),
    content: await prisma.siteSection.findMany(),
    media: await prisma.media.findMany(),
    users: await prisma.user.findMany({ select: { id: true, name: true, email: true, role: true } }),
  }

  fs.writeFileSync(path.join(backupDir, filename), JSON.stringify(allData, null, 2))
  await prisma.backup.create({ data: { filename, size: fs.statSync(path.join(backupDir, filename)).size, type: req.body.type || "manual" } })
  await logActivity({ userId: req.user?.id, action: "create", entity: "backup", entityId: filename, ip: req.ip })
  res.json({ ok: true, filename })
})

app.get("/api/backups", authenticate, authorize("admin"), async (_req, res) => {
  res.json(await prisma.backup.findMany({ orderBy: { createdAt: "desc" } }))
})

// ─── Notifications ────────────────────────────────────
app.get("/api/notifications", authenticate, async (req: AuthRequest, res) => {
  const items = await prisma.notification.findMany({ where: { userId: req.user?.id }, orderBy: { createdAt: "desc" }, take: 50 })
  const unread = await prisma.notification.count({ where: { userId: req.user?.id, read: false } })
  res.json({ items, unread })
})

app.put("/api/notifications/:id/read", authenticate, async (req, res) => {
  await prisma.notification.update({ where: { id: pid(req) }, data: { read: true } })
  res.json({ ok: true })
})

// ─── Public: Products for frontend ────────────────────
app.get("/api/public/products", async (req, res) => {
  const category = q(req, "category")
  const limit = q(req, "limit") || "20"
  const where: any = { available: true }
  if (category) where.categoryId = category
  const items = await prisma.product.findMany({ where, include: { images: { orderBy: { sortOrder: "asc" } }, category: true }, orderBy: { sortOrder: "asc" }, take: Number(limit) })
  res.json(items)
})

app.get("/api/public/product/:slug", async (req, res) => {
  const product = await prisma.product.findUnique({ where: { slug: (req.params as any).slug }, include: { images: { orderBy: { sortOrder: "asc" } }, category: true } })
  if (!product) return res.status(404).json({ error: "Product not found" })
  res.json(product)
})

app.get("/api/public/categories", async (_req, res) => {
  res.json(await prisma.category.findMany({ orderBy: { sortOrder: "asc" } }))
})

app.get("/api/public/settings", async (_req, res) => {
  const settings = await prisma.setting.findMany()
  const obj: Record<string, string> = {}
  settings.forEach((s: any) => { obj[s.key] = s.value })
  res.json(obj)
})

app.get("/api/public/content/:page", async (req, res) => {
  const sections = await prisma.siteSection.findMany({ where: { page: (req.params as any).page } })
  const obj: Record<string, any> = {}
  sections.forEach((s: any) => { obj[s.section] = JSON.parse(s.content) })
  res.json(obj)
})

// ─── Activity Log ─────────────────────────────────────
app.get("/api/activity", authenticate, async (req, res) => {
  const page = q(req, "page") || "1"
  const limit = q(req, "limit") || "50"
  const items = await prisma.activityLog.findMany({ include: { user: { select: { name: true, email: true } } }, orderBy: { createdAt: "desc" }, skip: (Number(page) - 1) * Number(limit), take: Number(limit) })
  const total = await prisma.activityLog.count()
  res.json({ items, total })
})

// ─── Start Server (local only) ──────────────────────
if (!process.env.VERCEL) {
  const server = app.listen(config.port, () => {
    console.log(`🚀 RugLuxury API running on port ${config.port}`)
  })
  function gracefulShutdown() {
    console.log("Shutting down gracefully...")
    server.close(() => prisma.$disconnect().then(() => process.exit(0)))
  }
  process.on("SIGTERM", gracefulShutdown)
  process.on("SIGINT", gracefulShutdown)
}

export default app
