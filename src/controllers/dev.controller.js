import crypto from 'crypto'
import { eq } from 'drizzle-orm'
import { db } from '../db/index.js'
import { developersTable } from '../db/schema.js'

export const registerDev = async (req, res) => {
  // 1. Extract email, password from req.body
      // 2. Validate input
      //    - email exists?
      //    - password length?
      // 3. Check if developer already exists
      //    - query developersTable where email = ?
      // 4. If exists:
      //    → return 409 (already registered)
      // 5. Hash password
      //    - salt + hash (reuse your current logic)
      // 6. Insert into developersTable
      // 7. Return success (201)
  
      const { email, password, firstName, lastName } = req.body;
  
      if (!email || !password) {
          return res.status(400).json({ error: "Email and password are required!" })
      }
  
      const exists = await db
          .select({ id: developersTable.id })
          .from(developersTable)
          .where(eq(developersTable.email, email))
          .limit(1)
  
      if (exists) {
          return res.status(409).json({ error: "User already exists!" })
      }
  
      const salt = crypto.randomBytes(16).toString('hex')
      const hash = crypto.createHash("sha256").update(password + salt).digest('hex')
  
      await db.insert(developersTable)
          .values({
              firstName,
              lastName: lastName ?? null,
              email,
              password: hash,
              salt
          })
  
      res.status(201).json({ message: "User registered successfully!" })
}

export const loginDev = async (req, res) => {
  // 1. Extract email, password
    // 2. Validate input
    // 3. Fetch developer from DB
    // 4. If not found:
    //    → return 401
    // 5. Hash incoming password with stored salt
    // 6. Compare with stored password
    // 7. If mismatch:
    //    → return 401
    // 8. Store in session:
    //    req.session.developer = {
    //      id,
    //      email
    //    }
    // 9. Return success
    const {email, password} = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required!" });
    }

    const developer = await db
        .select()
        .from(developersTable)
        .where(eq(developersTable.email, email))
        .limit(1)

    if (!developer) {
        return res.status(401).json({ message: "Invalid email or password." });
    }
    
    const hash = crypto.createHash("sha256").update(password + developer.salt).digest("hex");

    if(hash !== developer.password){
        return res.status(401).json({ message: "Invalid email or password." });
    }

    req.session.developer = {
        id: developer.id,
        email: developer.email,
    }

    return res.status(200).json({ success: true });
}
