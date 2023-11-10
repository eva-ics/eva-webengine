import * as path from "path";
import { defineConfig } from "vite";

const lib_name = "webengine";

export default defineConfig({
  build: {
    rollupOptions: {
      external: ["bmat/log", "bmat/dom", "bmat"]
    },
    lib: {
      entry: path.resolve(__dirname, "src/lib.ts"),
      name: lib_name,
      fileName: (format) => `${lib_name}.${format}.js`
    }
  }
});
