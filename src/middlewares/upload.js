const multer = require('multer');
const path = require('path');
const cloudinary = require('../config/cloudinary');
const HttpError = require('../utils/httpError');
const logger = require('../utils/logger');

const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB per file (unchanged)
const MAX_FILES = 5; // product images (unchanged)

// Real content types we accept, detected from the file's magic bytes.
const ALLOWED_MIME = new Set(['image/jpeg', 'image/png', 'image/webp']);
const ALLOWED_EXT = /^\.(jpe?g|png|webp)$/;

// file-type is ESM-only; a dynamic import() works from CommonJS on every supported Node.
let fileTypeModule;
const loadFileType = () => (fileTypeModule ||= import('file-type'));

/**
 * Stage 1 (multer, in memory): cheap checks on client-supplied MIME type and
 * extension, size and file-count limits. These alone are NOT trusted.
 */
const memoryUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE_SIZE, files: MAX_FILES },
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith('image/')) {
      return cb(new HttpError(400, 'Only image files allowed'), false);
    }
    if (!ALLOWED_EXT.test(path.extname(file.originalname).toLowerCase())) {
      return cb(new HttpError(400, 'Invalid image format'), false);
    }
    cb(null, true);
  },
});

const uploadBuffer = (buffer) =>
  new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      {
        folder: process.env.CLOUDINARY_FOLDER || 'bw-market',
        allowed_formats: ['jpg', 'jpeg', 'png', 'webp'],
        transformation: [{ width: 1200, crop: 'limit' }],
        resource_type: 'image',
      },
      (error, result) => (error ? reject(error) : resolve(result))
    );
    stream.end(buffer);
  });

/** Best-effort removal of already-uploaded images (e.g. when later validation fails). */
const deleteUploadedFiles = async (files = []) => {
  await Promise.allSettled(
    files.filter((f) => f && f.filename).map((f) => cloudinary.uploader.destroy(f.filename))
  );
};

/**
 * Stage 2: verify the real file type from the bytes (client MIME/extension can
 * be forged), and only then upload to Cloudinary. Populates `file.path` with the
 * hosted URL, exactly what multer-storage-cloudinary used to provide.
 */
const verifyAndUpload = async (req, res, next) => {
  const files = req.files ? [].concat(req.files) : req.file ? [req.file] : [];
  if (files.length === 0) return next();

  try {
    const { fileTypeFromBuffer } = await loadFileType();

    for (const file of files) {
      const detected = await fileTypeFromBuffer(file.buffer);
      if (!detected || !ALLOWED_MIME.has(detected.mime)) {
        throw new HttpError(400, 'Invalid image format');
      }
    }

    const uploaded = [];
    try {
      for (const file of files) {
        const result = await uploadBuffer(file.buffer);
        file.path = result.secure_url;
        file.filename = result.public_id;
        delete file.buffer; // free memory
        uploaded.push(file);
      }
    } catch (err) {
      await deleteUploadedFiles(uploaded);
      logger.error('Image upload to Cloudinary failed', err);
      throw new HttpError(502, 'Image upload failed. Please try again.');
    }
    next();
  } catch (err) {
    next(err);
  }
};

// Same call-sites as before: upload.array('images', 5) / upload.single('avatar').
// Express flattens the returned middleware arrays.
module.exports = {
  array: (field, max = MAX_FILES) => [memoryUpload.array(field, max), verifyAndUpload],
  single: (field) => [memoryUpload.single(field), verifyAndUpload],
  deleteUploadedFiles,
  MAX_FILE_SIZE,
};
