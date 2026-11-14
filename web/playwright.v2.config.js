import { defineConfig } from '@playwright/test'
export default defineConfig({
  testDir:'./tests', testMatch:['v2-product.spec.js','v2-paged.spec.js','v2-operations-conflicts.spec.js'],
  use:{baseURL:'http://127.0.0.1:4174'},
  webServer:{command:'npm run preview -- --host 127.0.0.1 --port 4174 --strictPort',url:'http://127.0.0.1:4174',reuseExistingServer:false},
})
