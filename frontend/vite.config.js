import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 3005,
    proxy: {
      '/auth': 'http://localhost:8005',
      '/scans': 'http://localhost:8005',
      '/findings': 'http://localhost:8005',
      '/health': 'http://localhost:8005',
    },
  },
});
