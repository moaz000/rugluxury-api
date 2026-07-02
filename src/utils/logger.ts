import { prisma } from "../prisma"

export async function logActivity(params: {
  userId?: string
  action: string
  entity: string
  entityId?: string
  details?: Record<string, unknown>
  ip?: string
}) {
  try {
    await prisma.activityLog.create({
      data: {
        userId: params.userId,
        action: params.action,
        entity: params.entity,
        entityId: params.entityId,
        details: params.details ? JSON.stringify(params.details) : null,
        ip: params.ip,
      },
    })
  } catch (e) {
    console.error("Failed to log activity:", e)
  }
}
