/**
 * BARON NEXUS — Full-Stack Express + Vite Server Entry Point (Port 3000)
 */

import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { createServer as createViteServer } from 'vite';
import { BaronDatabase } from './src/server/db.ts';
import { createApiRouter } from './src/server/api.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export async function createBaronApp(customDbPath?: string) {
  const app = express();
  const db = new BaronDatabase(customDbPath);

  app.use(express.json({ limit: '2mb' }));

  // Mount versioned REST API
  const apiRouter = createApiRouter(db);
  app.use('/api/v1', apiRouter);

  return { app, db };
}

async function startServer() {
  const PORT = 3000;
  const { app } = await createBaronApp();

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[BARON NEXUS] Enterprise Security Platform listening on http://0.0.0.0:${PORT}`);
  });
}

// Only start listening when executed directly (allows importing createBaronApp in tests)
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename)) {
  startServer();
}
