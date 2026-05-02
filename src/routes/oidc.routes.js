import { Router } from 'express'
import {
  getOpenIdConfiguration,
  getJwks,
  authorize,
  token,
  userinfo,
  getConsentData, 
  consent
} from '../controllers/oidc.controller.js'

const router = Router()

router.get('/.well-known/openid-configuration', getOpenIdConfiguration)
router.get('/.well-known/jwks.json', getJwks)
router.get('/auth', authorize)
router.post('/token', token)
router.get('/userinfo', userinfo)
router.post('/consent', consent)
router.get('/consent-data', getConsentData)

export default router
