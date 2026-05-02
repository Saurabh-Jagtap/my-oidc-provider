import { Router } from 'express'
import { getConsentPage, getLoginPage, getRegisterPage } from '../controllers/page.controller.js'

const router = Router()

router.get('/login.html', getLoginPage)
router.get('/register.html', getRegisterPage)
router.get('/consent.html', getConsentPage)

export default router
