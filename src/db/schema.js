import { integer, pgTable, timestamp, varchar, uuid, boolean, text } from "drizzle-orm/pg-core";

export const usersTable = pgTable("users", {
  id: uuid("id").primaryKey().defaultRandom(),
  firstName: varchar("first_name", { length: 25 }).notNull(),
  lastName: varchar("last_name", { length: 25 }),
  email: varchar("email", { length: 322 }).notNull().unique(),
  emailVerified: boolean("email_verified").default(false).notNull(),
  password: varchar("password", { length: 66 }).notNull(),
  salt: text("salt"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const developersTable = pgTable("developers", {
  id: uuid("id").primaryKey().defaultRandom(),
  firstName: varchar("first_name", { length: 25 }).notNull(),
  lastName: varchar("last_name", { length: 25 }),
  email: varchar("email", { length: 322 }).notNull().unique(),
  password: varchar("password", { length: 66 }).notNull(),
  salt: text("salt"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const clientsTable = pgTable("clients", {
  id: uuid("id").primaryKey().defaultRandom(),
  developerId: uuid("developer_id").notNull().references(() => developersTable.id),
  name: varchar("name", { length: 100 }).notNull(),
  clientId: varchar("client_id", { length: 100 }).notNull().unique(),
  clientSecret: text("client_secret"),
  redirectUris: text("redirect_uris").notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const refreshTokensTable = pgTable("refresh_tokens", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: uuid("user_id").notNull().references(() => usersTable.id, { onDelete: "cascade" }),
  clientId: varchar("client_id").notNull(),
  refreshTokenHash: text("refresh_token_hash").notNull(),
  expiresAt: timestamp("expires_at").notNull(),
  revoked: boolean("revoked").default(false),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const authorizationCodesTable = pgTable("authorization_codes", {
  id: uuid("id").primaryKey().defaultRandom(),
  codeHash: text("code_hash").notNull(),
  userId: uuid("user_id").notNull().references(() => usersTable.id, { onDelete: "cascade" }),
  clientId: varchar("client_id", { length: 100 }).notNull().references(() => clientsTable.clientId),
  redirectUri: text("redirect_uri").notNull(),
  codeChallenge: text("code_challenge").notNull(),
  scope: text("scope").notNull(),
  nonce: text(),
  expiresAt: timestamp("expires_at").notNull(),
  consumed: boolean("consumed").default(false),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const userConsentsTable = pgTable("user_consent", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: uuid("user_id").notNull().references(() => usersTable.id, {onDelete: "cascade"}),
  clientId: varchar("client_id").notNull(),
  scopes: text("scopes"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
},
  (table) => {
    return {
      userClientUnique: uniqueIndex("user_client_unique").on(
        table.userId,
        table.clientId
      )
    }
  })
