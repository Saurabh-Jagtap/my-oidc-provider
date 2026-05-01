import { Router } from 'express'
import { registerDev, loginDev } from '../controllers/dev.controller.js'

const router = Router()

router.post('/register', registerDev)
router.post('/login', loginDev)

export default router
