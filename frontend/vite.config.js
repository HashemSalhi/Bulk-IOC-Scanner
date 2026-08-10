import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
  ],
  build: {
    // Build straight into the Python package. FastAPI serves these files, so
    // an installed copy needs no Node and no second server.
    outDir: '../backend/bulk_ioc_scanner/web',
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        // Match the backend's actual bind host, which is IPv4. Using
        // "localhost" here can resolve to IPv6 ::1 and fail to connect.
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
})
