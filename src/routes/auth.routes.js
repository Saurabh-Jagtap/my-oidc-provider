import { Router } from 'express'
import { registerUser, loginUser, becomeDeveloper, logoutUser } from '../controllers/auth.controller.js'

const router = Router()

router.post('/register', registerUser)
router.post('/login', loginUser)
router.post('/logout', logoutUser)
router.post("/become-developer", becomeDeveloper);

export default router
