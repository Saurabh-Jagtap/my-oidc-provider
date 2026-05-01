import path from 'path'
import { fileURLToPath } from 'url'

const __filename = fileURLToPath(import.meta.url)

export const __dirname = path.resolve(path.dirname(__filename), '..')
