import { PrismaClient } from "@prisma/client"
import bcrypt from "bcryptjs"

const prisma = new PrismaClient()

async function main() {
  // Admin user
  const adminPassword = await bcrypt.hash("admin123", 12)
  await prisma.user.upsert({
    where: { email: "admin@rugluxury.com" },
    update: {},
    create: { name: "Admin", email: "admin@rugluxury.com", password: adminPassword, role: "admin" },
  })
  // Manager
  await prisma.user.upsert({
    where: { email: "manager@rugluxury.com" },
    update: {},
    create: { name: "Manager", email: "manager@rugluxury.com", password: await bcrypt.hash("manager123", 12), role: "manager" },
  })
  // Employee
  await prisma.user.upsert({
    where: { email: "employee@rugluxury.com" },
    update: {},
    create: { name: "Employee", email: "employee@rugluxury.com", password: await bcrypt.hash("employee123", 12), role: "employee" },
  })

  // Default settings
  const defaults: Record<string, string> = {
    site_name: "RugLuxury",
    site_description: "Handcrafted luxury rugs for the world's most beautiful spaces.",
    shipping_rate: "50",
    free_shipping_threshold: "500",
    tax_rate: "8.5",
    support_email: "support@rugluxury.com",
    support_phone: "+1 (800) 555-0199",
    whatsapp_number: "+971501234567",
    currency: "USD",
    language: "en",
    logo: "",
    favicon: "",
    theme: "dark",
    facebook: "",
    instagram: "",
    twitter: "",
    pinterest: "",
  }
  for (const [key, value] of Object.entries(defaults)) {
    await prisma.setting.upsert({ where: { key }, update: {}, create: { key, value } })
  }

  // Categories
  const categories = [
    { name: "Persian Silk", nameAr: "حرير فارسي", slug: "persian-silk", description: "Handwoven Persian silk rugs" },
    { name: "Moroccan", nameAr: "مغربي", slug: "moroccan", description: "Contemporary Moroccan designs" },
    { name: "Tribal", nameAr: "قبلي", slug: "tribal", description: "Traditional tribal patterns" },
    { name: "Contemporary", nameAr: "معاصر", slug: "contemporary", description: "Modern minimalist rugs" },
    { name: "Kilim", nameAr: "كليم", slug: "kilim", description: "Flatwoven kilim rugs" },
  ]
  for (const cat of categories) {
    await prisma.category.upsert({ where: { slug: cat.slug }, update: {}, create: cat })
  }

  console.log("✅ Seed completed!")
}

main()
  .catch((e) => { console.error(e); process.exit(1) })
  .finally(() => prisma.$disconnect())
