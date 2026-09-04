// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 mikey-san

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 5173,
    strictPort: true,
  },
});
