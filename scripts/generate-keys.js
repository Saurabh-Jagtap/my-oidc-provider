import { generateKeyPairSync } from 'node:crypto'
import { mkdirSync, writeFileSync } from 'node:fs'
import path from 'node:path'

const certDir = path.resolve('cert')
const privateKeyPath = path.join(certDir, 'private-key.pem')
const publicKeyPath = path.join(certDir, 'public-key.pub')

mkdirSync(certDir, { recursive: true })

const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem',
  },
  publicKeyEncoding: {
    type: 'spki',
    format: 'pem',
  },
})

writeFileSync(privateKeyPath, privateKey)
writeFileSync(publicKeyPath, publicKey)

console.log(`Generated private key: ${privateKeyPath}`)
console.log(`Generated public key: ${publicKeyPath}`)
