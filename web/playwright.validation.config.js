import {defineConfig} from '@playwright/test'
export default defineConfig({testDir:'./tests',testMatch:'v2-ai-validation.spec.js',workers:1,retries:0,use:{baseURL:'http://127.0.0.1:4178',trace:'off',video:'off',screenshot:'off'},webServer:{command:'npm run preview -- --host 127.0.0.1 --port 4178 --strictPort',url:'http://127.0.0.1:4178',reuseExistingServer:false}})
