import express from 'express'
import cors from 'cors'
import session from 'express-session'

import { corsOptions } from './config/cors.config.js'
import { sessionOptions } from './config/session.config.js'

import pageRoutes from './routes/page.routes.js'
import oidcRoutes from './routes/oidc.routes.js'
import authRoutes from './routes/auth.routes.js'
import devRoutes from './routes/dev.routes.js'
import clientRoutes from './routes/client.routes.js'
import { errorHandler, notFoundHandler } from './middlewares/error.middleware.js'

const app = express()

app.use(cors(corsOptions))
app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.use(session(sessionOptions))

app.use('/', pageRoutes)
app.use('/', oidcRoutes)
app.use('/', authRoutes)
app.use('/dev', devRoutes)
app.use('/clients', clientRoutes)

app.get("/health", (req, res) =>
    res.json({ message: "Server is healthy", healthy: true }),
);

app.use(notFoundHandler)
app.use(errorHandler)

export default app
