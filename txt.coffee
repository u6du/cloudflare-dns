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



host_li = (page=1)->
    for await i from page_get("zones",{per_page:50, page})
        yield [i.id,i.name]

page_get = (url, data)->
    data.page = 1
    while 1
        r = await request.get(url, data)

        for i in r.data.result
            yield i
        if data.page >= r.data.result_info.total_pages
            break
        data.page += 1


update_txt = (id, host, txt)->
    console.log host
    url = "zones/#{id}/dns_records"
    type = "TXT"
    name = "6du-boot."+host

    id = undefined
    for await i from page_get(url,{type})
        if i.name == name
            id = i.id
            break
    if id
        url+=("/"+id)
        method = "put"
    else
        method = "post"
    r = await request[method](
        url
        {
            type:"TXT"
            name:"6du-boot."+host
            content:txt
        }
    )
    console.log r

do ->
    txt = "0009.6du.host 0002.6du.host 0003.6du.host"
    for await [id,host] from host_li()
        await update_txt id,host,txt

