import mongoose from 'mongoose'

const releaseHistorySchema = new mongoose.Schema(
  {
    action: {
      type: String,
      required: true,
      enum: ['publish', 'delete_apk'],
    },
    actorEmail: {
      type: String,
      default: 'unknown',
      trim: true,
      lowercase: true,
    },
    version: {
      type: String,
      default: '',
      trim: true,
    },
    platform: {
      type: String,
      default: 'android',
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
    directDownloadUrl: {
      type: String,
      default: '',
    },
    notes: {
      type: String,
      default: '',
    },
    createdAt: {
      type: Date,
      default: () => new Date(),
      index: true,
    },
  },
  {
    minimize: false,
  }
)

const ReleaseHistory =
  mongoose.models.ReleaseHistory ??
  mongoose.model('ReleaseHistory', releaseHistorySchema)

export { ReleaseHistory }
