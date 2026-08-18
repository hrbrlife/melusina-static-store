import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  // Served at the ROOT of the default Bazaar by the melusina-store-sidecar
  // (handler.go http.FileServer(DistDir) mounts dist-publish/ at "/"). The old
  // gh-pages project-page base '/melusina-static-store/' made the built
  // index.html reference /melusina-static-store/assets/*.js which 404s under
  // root serving, so the SPA never mounted (empty #root → no search box). The
  // gh-pages source is retired; the default Bazaar is served at its origin root.
  base: '/',
});
