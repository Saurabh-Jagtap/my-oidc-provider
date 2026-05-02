import { Router } from 'express'
import { registerClient, getMyClients, getClientById, deleteClient } from '../controllers/client.controller.js'
import { requireDevAuth } from '../middlewares/requireDevAuth.middleware.js'

const router = Router()

router.post('/register', requireDevAuth, registerClient) // POST registerClient
router.get("/", getMyClients);                 // GET /clients
router.get("/:clientId", getClientById);       // GET /clients/:clientId
router.delete("/:clientId", deleteClient);     // DELETE /clients/:clientId

export default router
