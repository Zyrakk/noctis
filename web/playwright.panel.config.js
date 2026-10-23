import {defineConfig} from '@playwright/test'
export default defineConfig({testDir:'./tests',testMatch:'v2-panel.spec.js',workers:1,retries:0,use:{baseURL:'http://127.0.0.1:4186',trace:'off',video:'off'},timeout:30000,webServer:{command:'npm run preview -- --host 127.0.0.1 --port 4186 --strictPort',url:'http://127.0.0.1:4186',reuseExistingServer:false}})
