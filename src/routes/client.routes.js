import { Router } from 'express'
import { registerClient } from '../controllers/client.controller.js'
import { requireDevAuth } from '../middlewares/requireDevAuth.middleware.js'

const router = Router()

router.post('/register', requireDevAuth, registerClient)

export default router
