import { defineConfig } from 'vite';

export default defineConfig({
  // Worker URLs in a reusable library must resolve relative to the installed
  // package, not from the consuming application's `/public` root.
  base: './',
  build: {
    assetsInlineLimit: 0,
    lib: {
      entry: 'src/index.ts',
      formats: ['es'],
      fileName: 'index',
    },
    rollupOptions: {
      external: ['react'],
      output: {
        assetFileNames: 'assets/[name]-[hash][extname]',
        chunkFileNames: 'chunks/[name]-[hash].js',
      },
    },
    sourcemap: true,
    target: 'es2022',
  },
  test: {
    environment: 'node',
    coverage: {
      reporter: ['text', 'json-summary'],
    },
  },
  worker: {
    format: 'es',
  },
});
