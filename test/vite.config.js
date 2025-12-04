import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  root: path.resolve(__dirname),
  plugins: [react()],
  resolve: {
    alias: {
      'react-sunshine': path.resolve(__dirname, '../src/index.js'),
    },
  },
  server: {
    port: 3000,
    open: true,
  },
});

