import crypto from 'crypto'
import { db } from '../db/index.js'
import { clientsTable, usersTable } from '../db/schema.js'
import { eq, and } from "drizzle-orm";

export const getMyClients = async (req, res) => {
  try {
    if (!req.session?.user) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const userId = req.session.user.id;

    const clients = await db
      .select({
        id: clientsTable.id,
        name: clientsTable.name,
        clientId: clientsTable.clientId,
        redirectUris: clientsTable.redirectUris,
        createdAt: clientsTable.createdAt
      })
      .from(clientsTable)
      .where(
        and(
          eq(clientsTable.userId, userId),
          eq(clientsTable.revoked, false)
        )
      );

    return res.json({ clients });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "internal_server_error" });
  }
};

// Get single client (ownership enforced)
export const getClientById = async (req, res) => {
  try {
    if (!req.session?.user) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const { clientId } = req.params;
    const userId = req.session.user.id;

    const [client] = await db
      .select({
        id: clientsTable.id,
        name: clientsTable.name,
        clientId: clientsTable.clientId,
        redirectUris: clientsTable.redirectUris,
        createdAt: clientsTable.createdAt
      })
      .from(clientsTable)
      .where(
        and(
          eq(clientsTable.clientId, clientId),
          eq(clientsTable.userId, userId),
          eq(clientsTable.revoked, false)
        )
      )
      .limit(1);

    if (!client) {
      return res.status(404).json({ error: "Client not found" });
    }

    return res.json({ client });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "internal_server_error" });
  }
};

// POST register client
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
  try {
    if (!req.session?.user) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const { name, redirect_uris } = req.body;
    if (!name) {
      return res.status(400).json({ error: 'Client name is required' })
    }

    if (!Array.isArray(redirect_uris) || redirect_uris.length === 0) {
      return res.status(400).json({ error: 'redirect_uris must be a non-empty array' })
    }

    if (redirect_uris.length > 5) {
      return res.status(400).json({ error: "Too many redirect URIs" });
    }

    const validatedUris = [];
    for (const uri of redirect_uris) {
      try {
        const parsed = new URL(uri);

        if (!["http:", "https:"].includes(parsed.protocol)) {
          return res.status(400).json({ error: "Invalid protocol" });
        }

        validatedUris.push(parsed.toString());

      } catch {
        return res.status(400).json({ error: `Invalid redirect URI: ${uri}` })
      }
    }

    // Remove duplicates
    const uniqueUris = [...new Set(validatedUris)];

    const clientId = crypto.randomUUID();
    const clientSecret = crypto.randomBytes(32).toString('hex');

    const hashedSecret = crypto
      .createHash("sha256")
      .update(clientSecret)
      .digest("hex");

    const [client] = await db
      .insert(clientsTable)
      .values({
        userId: req.session.user.id,
        name,
        clientId,
        clientSecret: hashedSecret,
        redirectUris: JSON.stringify(uniqueUris)
      })
      .returning({
        id: clientsTable.id,
        name: clientsTable.name,
        clientId: clientsTable.clientId,
        redirectUris: clientsTable.redirectUris
      });

    return res.status(201).json({
      message: 'Client registered successfully!',
      client: {
        id: client.id,
        name: client.name,
        client_id: client.clientId,
        client_secret: clientSecret, // ONLY TIME WE RETURN THIS
        redirect_uris: JSON.parse(client.redirectUris)
      }
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "internal_server_error" });
  }
}

// Delete client (ownership enforced)
export const deleteClient = async (req, res) => {
  try {
    if (!req.session?.user) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const { clientId } = req.params;
    const userId = req.session.user.id;

    const [user] = await db
      .select()
      .from(usersTable)
      .where(eq(usersTable.id, req.session.user.id))
      .limit(1);

    if (!user || user.role !== "developer") {
      return res.status(403).json({ error: "Forbidden" });
    }

    const result = await db
      .update(clientsTable)
      .set({ revoked: true })
      .where(
        and(
          eq(clientsTable.clientId, clientId),
          eq(clientsTable.userId, userId)
        )
      )
      .returning();

    if (result.length === 0) {
      return res.status(404).json({ error: "Client not found or unauthorized" });
    }

    return res.json({ message: "Client revoked successfully" });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "internal_server_error" });
  }
};
