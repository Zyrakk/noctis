import {defineConfig} from '@playwright/test'
export default defineConfig({testDir:'./tests',testMatch:['v2-ai-real.spec.js'],workers:1,use:{ignoreHTTPSErrors:true},timeout:45000})
