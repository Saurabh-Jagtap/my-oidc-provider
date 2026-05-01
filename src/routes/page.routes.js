import { Router } from 'express'
import { getLoginPage, getRegisterPage } from '../controllers/page.controller.js'

const router = Router()

router.get('/login.html', getLoginPage)
router.get('/register.html', getRegisterPage)

export default router
