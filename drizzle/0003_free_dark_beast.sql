ALTER TABLE "user_consent" ALTER COLUMN "client_id" SET DATA TYPE varchar(100);--> statement-breakpoint
ALTER TABLE "user_consent" ALTER COLUMN "scopes" SET NOT NULL;