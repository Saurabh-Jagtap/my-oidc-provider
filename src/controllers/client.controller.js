import crypto from 'crypto'
import { db } from '../db/index.js'
import { clientsTable } from '../db/schema.js'

export const registerClient = async (req, res) => {
  // 1. Check developer session (already via middleware)
  // 2. Extract:
  //    - name
  //    - redirect_uris
  // 3. Validate:
  //    - redirect_uris is array
  //    - valid URLs
  // 4. Generate:
  //    - client_id
  //    - (optional) client_secret
  // 5. Store in DB:
  //    - client_id
  //    - developer_id (VERY IMPORTANT)
  //    - redirect_uris
  // 6. Return:
  //    - client_id (+ secret if needed)
  const { name, redirect_uris } = req.body;
  if (!name) {
    return res.status(400).json({ error: 'Client name is required' })
  }

  if (!Array.isArray(redirect_uris) || redirect_uris.length === 0) {
    return res.status(400).json({ error: 'redirect_uris must be a non-empty array' })
  }

  for (const uri of redirect_uris) {
    try {
      const parsed = new URL(uri);
      if (!["http:", "https:"].includes(parsed.protocol)) {
        return error;
      }
    } catch (error) {
      return res.status(400).json({ error: `Invalid redirect URI: ${uri}` })
    }
  }

  const clientId = crypto.randomUUID()
  // const clientSecret = crypto.randomBytes(32).toString('hex')

  const [client] = await db
    .insert(clientsTable)
    .values({
      developerId: req.session.developer.id,
      name,
      clientId,
      clientSecret: null,
      redirectUris: JSON.stringify(redirect_uris)
    })
    .returning({
      id: clientsTable.id,
      name: clientsTable.name,
      clientId: clientsTable.clientId,
      clientSecret: clientsTable.clientSecret,
      redirectUris: clientsTable.redirectUris
    })

  return res.status(201).json({
    message: 'Client registered successfully!',
    client: {
      id: client.id,
      name: client.name,
      client_id: client.clientId,
      client_secret: client.clientSecret,
      redirect_uris: JSON.parse(client.redirectUris)
    }
  })
}
