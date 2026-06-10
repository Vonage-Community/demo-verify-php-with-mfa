import { defineConfig } from 'vite';

const phpApiUrl = process.env.PHP_API_URL || 'http://localhost:8080';

export default defineConfig({
  root: 'public',

  build: {
    outDir: '../dist',
    emptyOutDir: true,
    target: 'esnext',
  },

  server: {
    proxy: {
      // Proxy all /api/* requests to the PHP application
      // e.g. /api/register → http://localhost:8080/register
      '/api': {
        target: phpApiUrl,
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ''),
      },
    },
  },
});
