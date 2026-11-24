import "dotenv/config";
import { createApp } from "./app.js";
import { loadConfig } from "./config.js";

const config = loadConfig();
createApp(config).listen(config.PORT, () => {
  console.log(`Authentication API listening on http://localhost:${config.PORT}`);
});
