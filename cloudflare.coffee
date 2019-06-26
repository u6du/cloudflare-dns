#!/usr/bin/env coffee

CONFIG = require './config'

module.exports = require('axios').create({
    baseURL: 'https://api.cloudflare.com/client/v4/'
    timeout: 90000
    headers:{
        'X-Auth-Key': CONFIG.CLOUDFLARE.KEY,
        'X-Auth-Email': CONFIG.CLOUDFLARE.EMAIL
    }
})
