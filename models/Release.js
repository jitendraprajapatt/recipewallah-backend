import mongoose from 'mongoose'

const releaseSchema = new mongoose.Schema(
  {
    key: {
      type: String,
      default: 'latestRelease',
      unique: true,
      index: true,
    },
    version: {
      type: String,
      required: true,
      trim: true,
    },
    platform: {
      type: String,
      enum: ['android', 'ios', 'both'],
      default: 'android',
    },
    releaseNotes: {
      type: String,
      default: '',
    },
    directDownloadUrl: {
      type: String,
      default: '',
    },
    playStoreUrl: {
      type: String,
      default: '',
    },
    appStoreUrl: {
      type: String,
      default: '',
    },
    fileName: {
      type: String,
      default: '',
    },
    fileSize: {
      type: Number,
      default: 0,
    },
    storagePath: {
      type: String,
      default: '',
    },
    updatedBy: {
      type: String,
      default: 'unknown',
    },
    updatedAt: {
      type: Date,
      default: () => new Date(),
    },
  },
  {
    minimize: false,
  }
)

const Release = mongoose.models.Release ?? mongoose.model('Release', releaseSchema)

export { Release }