import { createApp } from "./app.js";
import { assertRequiredEnv, config } from "./config/env.js";
import { connectDB, disconnectDB } from "./config/db.js";

async function main() {
  assertRequiredEnv();
  await connectDB(config.mongoUri);

  const app = createApp();
  const server = app.listen(config.port, () => {
    console.log(`Chef's Court API running on http://localhost:${config.port}`);
    console.log(`API docs: http://localhost:${config.port}/docs`);
  });

  const shutdown = (signal) => {
    console.log(`${signal} received, shutting down...`);
    server.close(async () => {
      await disconnectDB();
      process.exit(0);
    });
  };
  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));
}

main().catch((err) => {
  console.error("Failed to start server:", err.message);
  process.exit(1);
});
