import bcrypt from 'bcryptjs'
import cors from 'cors'
import dotenv from 'dotenv'
import express from 'express'
import fs from 'node:fs'
import fsp from 'node:fs/promises'
import jwt from 'jsonwebtoken'
import mongoose from 'mongoose'
import multer from 'multer'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { Dropbox } from 'dropbox'
import { Release } from './models/Release.js'
import { ReleaseHistory } from './models/ReleaseHistory.js'

dotenv.config()

const app = express()
const port = Number(process.env.PORT ?? 5000)
const mongoUri = process.env.MONGODB_URI
const jwtSecret = process.env.JWT_SECRET

const authDbName = (process.env.AUTH_DB_NAME ?? 'auth').trim()
const authCollectionName = (process.env.AUTH_COLLECTION_NAME ?? 'user').trim()
const authLoginField = (process.env.AUTH_LOGIN_FIELD ?? 'email').trim()
const authPasswordField = (process.env.AUTH_PASSWORD_FIELD ?? 'password').trim()
const authFallbackFields = (process.env.AUTH_FALLBACK_LOGIN_FIELDS ?? '')
  .split(',')
  .map((entry) => entry.trim())
  .filter(Boolean)

if (!mongoUri) {
  throw new Error('Missing MONGODB_URI in environment variables.')
}

if (!jwtSecret) {
  throw new Error('Missing JWT_SECRET in environment variables.')
}

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const uploadsDir = path.join(__dirname, 'uploads')

fs.mkdirSync(uploadsDir, { recursive: true })

const dbx = new Dropbox({ accessToken: process.env.DROPBOX_ACCESS_TOKEN })

const corsOrigin = (process.env.CORS_ORIGIN ?? 'https://preeminent-pudding-2f9e20.netlify.app')
  .split(',')
  .map((entry) => entry.trim())
  .filter(Boolean)

app.use(
  cors({
    origin: corsOrigin.length === 1 ? corsOrigin[0] : corsOrigin,
  })
)
app.use(express.json())
app.use('/uploads', express.static(uploadsDir))

function sanitizeFileName(fileName) {
  return fileName.replace(/[^a-zA-Z0-9._-]/g, '-')
}

function escapeRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function resolvePublicBaseUrl(request) {
  const configured = (process.env.PUBLIC_BASE_URL ?? '').trim()
  if (configured) {
    return configured.replace(/\/+$/, '')
  }

  return `${request.protocol}://${request.get('host')}`
}

function normalizeReleasePayload(releaseDocument) {
  if (!releaseDocument) {
    return null
  }

  const release = releaseDocument.toObject ? releaseDocument.toObject() : releaseDocument
  delete release._id
  delete release.__v
  delete release.key
  return release
}

function normalizeHistoryPayload(entryDocument) {
  const entry = entryDocument.toObject ? entryDocument.toObject() : entryDocument
  return {
    id: String(entry._id),
    action: entry.action,
    actorEmail: entry.actorEmail,
    version: entry.version,
    platform: entry.platform,
    fileName: entry.fileName,
    fileSize: entry.fileSize,
    storagePath: entry.storagePath,
    directDownloadUrl: entry.directDownloadUrl,
    notes: entry.notes,
    createdAt: entry.createdAt,
  }
}

function getAuthUsersCollection() {
  return mongoose.connection
    .useDb(authDbName, { useCache: true })
    .collection(authCollectionName)
}

function resolvePasswordHash(userDocument) {
  const configuredFieldValue = userDocument?.[authPasswordField]
  if (typeof configuredFieldValue === 'string' && configuredFieldValue.length > 0) {
    return configuredFieldValue
  }

  const fallbackCandidates = [
    userDocument?.passwordHash,
    userDocument?.password,
    userDocument?.hash,
  ]

  return fallbackCandidates.find((value) => typeof value === 'string' && value.length > 0) ?? ''
}

function resolveUserEmail(userDocument, loginInput) {
  if (typeof userDocument?.email === 'string' && userDocument.email.trim()) {
    return userDocument.email.trim().toLowerCase()
  }

  const loginValue = userDocument?.[authLoginField]
  if (typeof loginValue === 'string' && loginValue.trim()) {
    return loginValue.trim().toLowerCase()
  }

  return String(loginInput).trim().toLowerCase()
}

function buildLoginLookup(loginInput) {
  const normalizedInput = String(loginInput).trim()
  const escapedInput = escapeRegex(normalizedInput)

  const searchFields = [authLoginField, ...authFallbackFields]
  const orConditions = searchFields.map((field) => ({
    [field]: {
      $regex: `^${escapedInput}$`,
      $options: 'i',
    },
  }))

  if (orConditions.length === 1) {
    return orConditions[0]
  }

  return { $or: orConditions }
}

function createAuthToken(userDocument, loginInput) {
  const userId = userDocument?._id ? String(userDocument._id) : ''
  const email = resolveUserEmail(userDocument, loginInput)

  return jwt.sign(
    {
      sub: userId,
      email,
    },
    jwtSecret,
    { expiresIn: '12h' }
  )
}

async function requireAuth(request, response, next) {
  const authorizationHeader = request.headers.authorization ?? ''
  const token = authorizationHeader.startsWith('Bearer ')
    ? authorizationHeader.slice('Bearer '.length).trim()
    : ''

  if (!token) {
    response.status(401).json({ message: 'Authentication token is required.' })
    return
  }

  try {
    const payload = jwt.verify(token, jwtSecret)
    request.user = {
      id: String(payload.sub ?? ''),
      email: String(payload.email ?? 'unknown'),
    }

    next()
  } catch {
    response.status(401).json({ message: 'Invalid or expired authentication token.' })
  }
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 300 * 1024 * 1024,
  },
  fileFilter: (_request, file, callback) => {
    if (/\.apk$/i.test(file.originalname)) {
      callback(null, true)
      return
    }

    callback(new Error('Only .apk files are allowed.'))
  },
})

function uploadSingleApk(request, response, next) {
  upload.single('appFile')(request, response, (error) => {
    if (error) {
      response.status(400).json({ message: error.message })
      return
    }

    next()
  })
}

async function deleteLocalUpload(storagePath) {
  if (!storagePath) {
    return false
  }

  if (storagePath.startsWith('dropbox:')) {
    const dbxPath = storagePath.slice('dropbox:'.length)
    try {
      await dbx.filesDeleteV2({ path: dbxPath })
      return true
    } catch (error) {
      console.error('Dropbox file deletion failed:', error)
      return false
    }
  }

  if (!/^uploads[\\/]/i.test(storagePath)) {
    return false
  }

  const relativePath = storagePath.replace(/^uploads[\\/]/i, '')
  const candidatePath = path.resolve(uploadsDir, relativePath)
  const uploadsRoot = path.resolve(uploadsDir)

  if (
    candidatePath !== uploadsRoot &&
    !candidatePath.startsWith(`${uploadsRoot}${path.sep}`)
  ) {
    return false
  }

  try {
    await fsp.unlink(candidatePath)
    return true
  } catch (error) {
    if (error?.code === 'ENOENT') {
      return false
    }

    throw error
  }
}

async function appendReleaseHistory({ action, actorEmail, release, notes }) {
  await ReleaseHistory.create({
    action,
    actorEmail,
    version: release.version ?? '',
    platform: release.platform ?? 'android',
    fileName: release.fileName ?? '',
    fileSize: Number(release.fileSize ?? 0),
    storagePath: release.storagePath ?? '',
    directDownloadUrl: release.directDownloadUrl ?? '',
    notes: notes ?? '',
    createdAt: new Date(),
  })
}

app.get('/health', (_request, response) => {
  response.json({ status: 'ok' })
})

app.post('/api/auth/login', async (request, response) => {
  const loginInput = String(request.body?.login ?? request.body?.email ?? '').trim()
  const password = String(request.body?.password ?? '')

  if (!loginInput || !password) {
    response.status(400).json({ message: 'Email/username and password are required.' })
    return
  }

  try {
    const usersCollection = getAuthUsersCollection()
    const userDocument = await usersCollection.findOne(buildLoginLookup(loginInput))

    if (!userDocument) {
      response.status(401).json({ message: 'Invalid email or password.' })
      return
    }

    const passwordHash = resolvePasswordHash(userDocument)
    if (!passwordHash) {
      response.status(401).json({ message: 'Invalid email or password.' })
      return
    }

    const isPasswordValid = await bcrypt.compare(password, passwordHash)

    if (!isPasswordValid) {
      response.status(401).json({ message: 'Invalid email or password.' })
      return
    }

    response.json({
      token: createAuthToken(userDocument, loginInput),
      user: {
        email: resolveUserEmail(userDocument, loginInput),
      },
    })
  } catch {
    response.status(500).json({ message: 'Login failed. Please try again.' })
  }
})

app.get('/api/release', async (_request, response) => {
  try {
    const latestRelease = await Release.findOne({ key: 'latestRelease' }).lean()

    response.json({
      release: normalizeReleasePayload(latestRelease),
    })
  } catch {
    response.status(500).json({ message: 'Could not load release data.' })
  }
})

app.get('/api/admin/history', requireAuth, async (request, response) => {
  const requestedLimit = Number.parseInt(String(request.query?.limit ?? '25'), 10)
  const limit = Number.isFinite(requestedLimit)
    ? Math.max(1, Math.min(100, requestedLimit))
    : 25

  try {
    const historyEntries = await ReleaseHistory.find({})
      .sort({ createdAt: -1 })
      .limit(limit)
      .lean()

    response.json({
      history: historyEntries.map(normalizeHistoryPayload),
    })
  } catch {
    response.status(500).json({ message: 'Could not load release history.' })
  }
})

app.post('/api/release', requireAuth, uploadSingleApk, async (request, response) => {
  const version = String(request.body?.version ?? '').trim()
  const platformInput = String(request.body?.platform ?? '').trim()
  const platform = ['android', 'ios', 'both'].includes(platformInput)
    ? platformInput
    : 'android'
  const releaseNotes = String(request.body?.releaseNotes ?? '').trim()
  let directDownloadUrl = String(request.body?.directDownloadUrl ?? '').trim()
  const playStoreUrl = String(request.body?.playStoreUrl ?? '').trim()
  const appStoreUrl = String(request.body?.appStoreUrl ?? '').trim()

  if (!version) {
    response.status(400).json({ message: 'Version is required.' })
    return
  }

  try {
    const existingRelease = await Release.findOne({ key: 'latestRelease' }).lean()

    let fileName = existingRelease?.fileName ?? ''
    let fileSize = existingRelease?.fileSize ?? 0
    let storagePath = existingRelease?.storagePath ?? ''

    if (request.file) {
      fileName = request.file.originalname
      fileSize = request.file.size
      
      const dropboxFilename = `${Date.now()}-${sanitizeFileName(fileName)}`
      const dropboxPath = `/${dropboxFilename}`

      try {
        await dbx.filesUpload({ path: dropboxPath, contents: request.file.buffer })
        const sharedLinkDetails = await dbx.sharingCreateSharedLinkWithSettings({ path: dropboxPath })
        
        const url = sharedLinkDetails.result.url
        directDownloadUrl = url.replace('?dl=0', '?dl=1').replace('&dl=0', '&dl=1')
        storagePath = `dropbox:${dropboxPath}`
      } catch (error) {
        console.error('Dropbox upload failed:', error)
        response.status(500).json({ message: 'Dropbox upload failed. Check the token and logs.' })
        return
      }
    }

    if (!directDownloadUrl && !playStoreUrl && !appStoreUrl) {
      response.status(400).json({
        message: 'Add at least one download link or upload an APK file.',
      })
      return
    }

    const nextRelease = await Release.findOneAndUpdate(
      { key: 'latestRelease' },
      {
        $set: {
          version,
          platform,
          releaseNotes,
          directDownloadUrl,
          playStoreUrl,
          appStoreUrl,
          fileName,
          fileSize,
          storagePath,
          updatedBy: request.user.email,
          updatedAt: new Date(),
        },
      },
      {
        upsert: true,
        new: true,
        setDefaultsOnInsert: true,
      }
    ).lean()

    await appendReleaseHistory({
      action: 'publish',
      actorEmail: request.user.email,
      release: nextRelease,
      notes: request.file
        ? 'Release published with uploaded APK.'
        : 'Release metadata updated without APK upload.',
    })

    response.json({
      release: normalizeReleasePayload(nextRelease),
    })
  } catch {
    response.status(500).json({ message: 'Failed to save release.' })
  }
})

app.delete('/api/release/apk', requireAuth, async (request, response) => {
  try {
    const releaseDocument = await Release.findOne({ key: 'latestRelease' })

    if (!releaseDocument) {
      response.status(404).json({ message: 'No release exists yet.' })
      return
    }

    const previousStoragePath = releaseDocument.storagePath ?? ''
    const previousDirectDownloadUrl = releaseDocument.directDownloadUrl ?? ''
    const removedFile = await deleteLocalUpload(previousStoragePath)

    const isDropbox = previousStoragePath.startsWith('dropbox:')
    const shouldClearDirectDownload = isDropbox || (previousStoragePath
      ? previousDirectDownloadUrl.includes(previousStoragePath)
      : /\/uploads\//i.test(previousDirectDownloadUrl))

    releaseDocument.fileName = ''
    releaseDocument.fileSize = 0
    releaseDocument.storagePath = ''
    if (shouldClearDirectDownload) {
      releaseDocument.directDownloadUrl = ''
    }
    releaseDocument.updatedBy = request.user.email
    releaseDocument.updatedAt = new Date()

    await releaseDocument.save()

    const releasePayload = normalizeReleasePayload(releaseDocument)

    await appendReleaseHistory({
      action: 'delete_apk',
      actorEmail: request.user.email,
      release: releasePayload,
      notes: removedFile
        ? 'APK removed from server storage and release metadata cleaned.'
        : 'Release APK metadata cleaned (file was not found on disk).',
    })

    response.json({
      release: releasePayload,
      removedFile,
    })
  } catch {
    response.status(500).json({ message: 'Failed to delete APK file.' })
  }
})

app.use((_request, response) => {
  response.status(404).json({ message: 'Route not found.' })
})

async function startServer() {
  await mongoose.connect(mongoUri)

  app.listen(port, () => {
    console.log(`RecipeWallah API server listening on port ${port}`)
  })
}

startServer().catch((error) => {
  console.error('Failed to start RecipeWallah API server', error)
  process.exit(1)
})
