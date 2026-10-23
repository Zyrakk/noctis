const {defineConfig}=require('../../../web/node_modules/@playwright/test')
module.exports=defineConfig({testDir:__dirname,testMatch:'real_ai.spec.cjs',workers:1,retries:0,reporter:'line',timeout:600000,outputDir:'/tmp/noctis-real-ai-browser-artifacts',use:{ignoreHTTPSErrors:true,trace:'off',video:'off',screenshot:'off'}})
