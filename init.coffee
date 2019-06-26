#!/usr/bin/env coffee

request = require('./cloudflare')

add = (user_id, host) ->
    account ={id:user_id}
    data = {
        name:host
        account
        type:'full'
        jump_start:false
    }
    try
        r = await request.post(
            "zones"
            data
        )
    catch err
        if err.response
            response = err.response
            console.log response.status
            console.log response.statusText
            console.log response.data
        else
            console.log err
        return

    console.log r.data


do ->

    r = await request.get(
        "accounts?page=1&per_page=20&direction=desc"
    )
    console.log r.data.result
    user_id = r.data.result[0].id

    require('line-reader').eachLine(
        "#{__dirname}/host.txt"
        (line)->
            host = line.trim()
            if not host
                return
            console.log host
            await add user_id,host
    )
    # await add user_id,"6du.world"
    # user = (await cf.user.read()).result
    # console.log user
    # user_id = user.id
    # # user_id = user.username
    # try
    #     r = await cf.zones.add({
    #         name:"6du.tv",
    #         account:{id:user_id},
    #         jump_start:false,
    #         type:"full"
    #     })
    # catch err
    #     console.log err
    #     return
    # console.log r
