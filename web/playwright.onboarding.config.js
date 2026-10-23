import {defineConfig} from '@playwright/test'
export default defineConfig({testDir:'./tests',testMatch:'v2-onboarding-real.spec.js',workers:1,use:{ignoreHTTPSErrors:true}})
