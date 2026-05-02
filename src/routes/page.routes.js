import { Router } from 'express'
import { getBecomeDev, getConsentPage, getDevDashboard, getLoginPage, getRegisterPage, getHome } from '../controllers/page.controller.js'
import { requireDevAuth } from '../middlewares/requireDevAuth.middleware.js'

const router = Router()

router.get('/login.html', getLoginPage)
router.get('/register.html', getRegisterPage)
router.get('/consent.html', getConsentPage)
router.get('/dev-dashboard.html', requireDevAuth, getDevDashboard);
router.get('/become-dev.html', getBecomeDev);
router.get('/home.html', getHome)

export default router
