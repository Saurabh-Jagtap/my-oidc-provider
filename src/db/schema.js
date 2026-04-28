import { integer, pgTable, timestamp, varchar, uuid, boolean, text } from "drizzle-orm/pg-core";

export const usersTable = pgTable("users", {
  id: uuid("id").primaryKey().defaultRandom(),
  firstName: varchar("first_name", { length: 25 }).notNull(),
  lastName: varchar("last_name", { length: 25 }),
  email: varchar("email",{ length: 322 }).notNull().unique(),
  emailVerified: boolean("email_verified").default(false).notNull(),
  password: varchar("password",{length: 66}).notNull(),
  salt: text("salt"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});
