import app from './app.js'
import 'dotenv/config'

const port = process.env.PORT || 3000

app.listen(port, () => {
  console.log(`Server listening on port: ${port}`)
})




































// import express from 'express'
// import dotenv from 'dotenv/config'
// import { generateKeyPairSync } from 'crypto'
// import { exportJWK, jwtVerify, SignJWT } from 'jose'
// import crypto from 'crypto'
// import session from 'express-session'
// import cors from 'cors'
// import path from 'path'
// import { fileURLToPath } from 'url'
// import { db } from './db/index.js'
// import { developersTable, usersTable } from './db/schema.js'
// import { eq } from 'drizzle-orm'

// const app = express();
// const port = process.env.PORT || 3000;

// app.use(express.json())
// // app.use(express.static(path.join(__dirname, 'public')))

// app.listen(port, () => {
//     console.log(`Server listening on port: ${port}`)
// })
