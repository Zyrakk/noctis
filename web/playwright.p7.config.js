import { defineConfig } from '@playwright/test'
export default defineConfig({
 testDir:'./tests',testMatch:['v2-p7.spec.js','v2-p7-real.spec.js','v2-operations-real.spec.js'],
 use:{baseURL:'http://127.0.0.1:4175',ignoreHTTPSErrors:true},
 webServer:{command:'npm run preview -- --host 127.0.0.1 --port 4175 --strictPort',url:'http://127.0.0.1:4175',reuseExistingServer:false},
})
