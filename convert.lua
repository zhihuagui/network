-- Clash Subscription Parser (Lua 5.1 Compatible)
-- No curl | No goto | No bit library | Regex Parsing | English Logs
-- Usage: lua clash-parser.lua <temp_file> <output_yaml>

-- ===================== Core Utils (No bit library) ======================
-- Simple log function (English only)
local function log(level, msg)
    local time = os.date("%H:%M:%S")
    print(string.format("[%s] [%s] %s", time, level, msg))
end

-- 1. URL Decode (Native Lua, support Chinese/emoji)
local function url_decode(str)
    if not str then return "" end
    str = string.gsub(str, "+", " ")
    str = string.gsub(str, "%%(%x%x)", function(h)
        return string.char(tonumber(h, 16))
    end)
    return str
end

-- 2. Base64 Decode (Pure Lua, no bit library)
local function base64_decode(data)
    local b = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    local t = {}
    for i = 1, #b do t[b:sub(i, i)] = i - 1 end

    -- 1. 过滤非法字符
    data = data:gsub('[^'..b..'=]', '')

    -- 2. 重要：补齐缺损的等号 (Padding)
    -- Base64 长度必须是 4 的倍数
    local rem = #data % 4
    if rem > 0 then
        data = data .. string.rep('=', 4 - rem)
    end

    -- 3. 解码逻辑
    local function decode_group(chunk)
        local c1, c2, c3, c4 = chunk:sub(1,1), chunk:sub(2,2), chunk:sub(3,3), chunk:sub(4,4)
        local v1, v2, v3, v4 = t[c1], t[c2], t[c3], t[c4]
        
        local res = ""
        
        -- 第一个字节：取 v1 全部 6 位 + v2 的高 2 位
        local b1 = v1 * 4 + math.floor(v2 / 16)
        res = res .. string.char(b1 % 256)

        -- 第二个字节：取 v2 的低 4 位 + v3 的高 4 位
        if c3 ~= '=' then
            local b2 = (v2 % 16) * 16 + math.floor(v3 / 4)
            res = res .. string.char(b2 % 256)
            
            -- 第三个字节：取 v3 的低 2 位 + v4 全部 6 位
            if c4 ~= '=' then
                local b3 = (v3 % 4) * 64 + v4
                res = res .. string.char(b3 % 256)
            end
        end
        return res
    end

    return (data:gsub('(....)', decode_group))
end

-- 3. Read subscription from temp file (from shell)
local function read_subscription(temp_file)
    log("INFO", "Reading subscription from file: " .. temp_file)
    local file = io.open(temp_file, "r")
    if not file then
        log("ERROR", "Failed to open temp file: " .. temp_file)
        return nil
    end
    local content = file:read("*a")
    file:close()
    
    if content == "" then
        log("ERROR", "Temp file is empty")
        return nil
    end
    return content
end

-- 4. Parse ss:// links with single regex (no goto, Lua 5.1 compatible)
local function parse_ss_links(content)
    local proxies = {}
    
    -- 逐行匹配 ss:// 协议
    -- 格式: ss://{userinfo}@{server}:{port}#{name}
    for line in content:gmatch("ss://%S+") do
        -- 使用模式匹配提取各个部分
        -- ^ss://           匹配开头
        -- ([^@]+)          匹配 @ 之前的所有内容 (userinfo)
        -- @                分隔符
        -- ([^:]+)          匹配 : 之前的内容 (server)
        -- :                分隔符
        -- ([^#%s]+)        匹配 # 或空格之前的内容 (port)
        -- #?               可选的 #
        -- (.*)             匹配剩下的所有内容 (name)
        local userinfo_b64, server, port, name_encoded = line:match("^ss://([^@]+)@([^:]+):([^#%s]+)#?(.*)")
        
        if userinfo_b64 then
            -- 解码加密信息 (通常是 method:password)
            local userinfo = base64_decode(userinfo_b64)
            local method, password = userinfo:match("([^:]+):(.*)")
            
            -- 解码节点名称
            local name = url_decode(name_encoded or "")
            
            table.insert(proxies, {
                method = method,
                password = password,
                server = server,
                port = port,
                name = name,
                raw = line -- 保留原始链接供参考
            })
        end
    end
    
    return proxies
end

-- 5. Generate final YAML (match your simplified template)
local function generate_final_yaml(proxies, output_yaml)
    if #proxies == 0 then
        log("ERROR", "No valid nodes to generate YAML")
        return false
    end

    -- Your simplified YAML template
    local yaml_template = [[mixed-port: 7890
allow-lan: true
bind-address: '*'
mode: rule
log-level: info
external-controller: '127.0.0.1:9090'
dns:
    enable: true
    ipv6: false
    default-nameserver: [223.5.5.5, 119.29.29.29]
    enhanced-mode: fake-ip
    fake-ip-range: 198.18.0.1/16
    use-hosts: true
    nameserver: ['https://doh.pub/dns-query', 'https://dns.alidns.com/dns-query']
    fallback: ['https://doh-pure.onedns.net/dns-query', 'https://ada.openbld.net/dns-query', 'https://223.5.5.5/dns-query', 'https://223.6.6.6/dns-query']
    fallback-filter: { geoip: true, ipcidr: [240.0.0.0/4, 0.0.0.0/32] }
proxies:
${proxies_list}proxy-groups:
    - { name: 天路云, type: select, proxies: [自动选择, 故障转移, ${proxy_names_list}] }
    - { name: 自动选择, type: url-test, proxies: [${proxy_names_list}], url: 'http://www.gstatic.com/generate_204', interval: 86400 }
    - { name: 故障转移, type: fallback, proxies: [${proxy_names_list}], url: 'http://www.gstatic.com/generate_204', interval: 7200 }
rules:
    - 'DOMAIN,dingyue.site,DIRECT'
    - 'DOMAIN-SUFFIX,services.googleapis.cn,天路云'
    - 'DOMAIN-SUFFIX,xn--ngstr-lra8j.com,天路云'
    - 'DOMAIN,safebrowsing.urlsec.qq.com,DIRECT'
    - 'DOMAIN,safebrowsing.googleapis.com,DIRECT'
    - 'DOMAIN,developer.apple.com,天路云'
    - 'DOMAIN-SUFFIX,digicert.com,天路云'
    - 'DOMAIN,ocsp.apple.com,天路云'
    - 'DOMAIN,ocsp.comodoca.com,天路云'
    - 'DOMAIN,ocsp.usertrust.com,天路云'
    - 'DOMAIN,ocsp.sectigo.com,天路云'
    - 'DOMAIN,ocsp.verisign.net,天路云'
    - 'DOMAIN-SUFFIX,apple-dns.net,天路云'
    - 'DOMAIN,testflight.apple.com,天路云'
    - 'DOMAIN,sandbox.itunes.apple.com,天路云'
    - 'DOMAIN,itunes.apple.com,天路云'
    - 'DOMAIN-SUFFIX,apps.apple.com,天路云'
    - 'DOMAIN-SUFFIX,blobstore.apple.com,天路云'
    - 'DOMAIN,cvws.icloud-content.com,天路云'
    - 'DOMAIN-SUFFIX,mzstatic.com,DIRECT'
    - 'DOMAIN-SUFFIX,itunes.apple.com,DIRECT'
    - 'DOMAIN-SUFFIX,icloud.com,DIRECT'
    - 'DOMAIN-SUFFIX,icloud-content.com,DIRECT'
    - 'DOMAIN-SUFFIX,me.com,DIRECT'
    - 'DOMAIN-SUFFIX,aaplimg.com,DIRECT'
    - 'DOMAIN-SUFFIX,cdn20.com,DIRECT'
    - 'DOMAIN-SUFFIX,cdn-apple.com,DIRECT'
    - 'DOMAIN-SUFFIX,akadns.net,DIRECT'
    - 'DOMAIN-SUFFIX,akamaiedge.net,DIRECT'
    - 'DOMAIN-SUFFIX,edgekey.net,DIRECT'
    - 'DOMAIN-SUFFIX,mwcloudcdn.com,DIRECT'
    - 'DOMAIN-SUFFIX,mwcname.com,DIRECT'
    - 'DOMAIN-SUFFIX,apple.com,DIRECT'
    - 'DOMAIN-SUFFIX,apple-cloudkit.com,DIRECT'
    - 'DOMAIN-SUFFIX,apple-mapkit.com,DIRECT'
    - 'DOMAIN-SUFFIX,126.com,DIRECT'
    - 'DOMAIN-SUFFIX,126.net,DIRECT'
    - 'DOMAIN-SUFFIX,127.net,DIRECT'
    - 'DOMAIN-SUFFIX,163.com,DIRECT'
    - 'DOMAIN-SUFFIX,360buyimg.com,DIRECT'
    - 'DOMAIN-SUFFIX,36kr.com,DIRECT'
    - 'DOMAIN-SUFFIX,acfun.tv,DIRECT'
    - 'DOMAIN-SUFFIX,air-matters.com,DIRECT'
    - 'DOMAIN-SUFFIX,aixifan.com,DIRECT'
    - 'DOMAIN-KEYWORD,alicdn,DIRECT'
    - 'DOMAIN-KEYWORD,alipay,DIRECT'
    - 'DOMAIN-KEYWORD,taobao,DIRECT'
    - 'DOMAIN-SUFFIX,amap.com,DIRECT'
    - 'DOMAIN-SUFFIX,autonavi.com,DIRECT'
    - 'DOMAIN-KEYWORD,baidu,DIRECT'
    - 'DOMAIN-SUFFIX,bdimg.com,DIRECT'
    - 'DOMAIN-SUFFIX,bdstatic.com,DIRECT'
    - 'DOMAIN-SUFFIX,bilibili.com,DIRECT'
    - 'DOMAIN-SUFFIX,bilivideo.com,DIRECT'
    - 'DOMAIN-SUFFIX,caiyunapp.com,DIRECT'
    - 'DOMAIN-SUFFIX,clouddn.com,DIRECT'
    - 'DOMAIN-SUFFIX,cnbeta.com,DIRECT'
    - 'DOMAIN-SUFFIX,cnbetacdn.com,DIRECT'
    - 'DOMAIN-SUFFIX,cootekservice.com,DIRECT'
    - 'DOMAIN-SUFFIX,csdn.net,DIRECT'
    - 'DOMAIN-SUFFIX,ctrip.com,DIRECT'
    - 'DOMAIN-SUFFIX,dgtle.com,DIRECT'
    - 'DOMAIN-SUFFIX,dianping.com,DIRECT'
    - 'DOMAIN-SUFFIX,douban.com,DIRECT'
    - 'DOMAIN-SUFFIX,doubanio.com,DIRECT'
    - 'DOMAIN-SUFFIX,duokan.com,DIRECT'
    - 'DOMAIN-SUFFIX,easou.com,DIRECT'
    - 'DOMAIN-SUFFIX,ele.me,DIRECT'
    - 'DOMAIN-SUFFIX,feng.com,DIRECT'
    - 'DOMAIN-SUFFIX,fir.im,DIRECT'
    - 'DOMAIN-SUFFIX,frdic.com,DIRECT'
    - 'DOMAIN-SUFFIX,g-cores.com,DIRECT'
    - 'DOMAIN-SUFFIX,godic.net,DIRECT'
    - 'DOMAIN-SUFFIX,gtimg.com,DIRECT'
    - 'DOMAIN,cdn.hockeyapp.net,DIRECT'
    - 'DOMAIN-SUFFIX,hongxiu.com,DIRECT'
    - 'DOMAIN-SUFFIX,hxcdn.net,DIRECT'
    - 'DOMAIN-SUFFIX,iciba.com,DIRECT'
    - 'DOMAIN-SUFFIX,ifeng.com,DIRECT'
    - 'DOMAIN-SUFFIX,ifengimg.com,DIRECT'
    - 'DOMAIN-SUFFIX,ipip.net,DIRECT'
    - 'DOMAIN-SUFFIX,iqiyi.com,DIRECT'
    - 'DOMAIN-SUFFIX,jd.com,DIRECT'
    - 'DOMAIN-SUFFIX,jianshu.com,DIRECT'
    - 'DOMAIN-SUFFIX,knewone.com,DIRECT'
    - 'DOMAIN-SUFFIX,le.com,DIRECT'
    - 'DOMAIN-SUFFIX,lecloud.com,DIRECT'
    - 'DOMAIN-SUFFIX,lemicp.com,DIRECT'
    - 'DOMAIN-SUFFIX,licdn.com,DIRECT'
    - 'DOMAIN-SUFFIX,luoo.net,DIRECT'
    - 'DOMAIN-SUFFIX,meituan.com,DIRECT'
    - 'DOMAIN-SUFFIX,meituan.net,DIRECT'
    - 'DOMAIN-SUFFIX,mi.com,DIRECT'
    - 'DOMAIN-SUFFIX,miaopai.com,DIRECT'
    - 'DOMAIN-SUFFIX,microsoft.com,DIRECT'
    - 'DOMAIN-SUFFIX,microsoftonline.com,DIRECT'
    - 'DOMAIN-SUFFIX,miui.com,DIRECT'
    - 'DOMAIN-SUFFIX,miwifi.com,DIRECT'
    - 'DOMAIN-SUFFIX,mob.com,DIRECT'
    - 'DOMAIN-SUFFIX,netease.com,DIRECT'
    - 'DOMAIN-SUFFIX,office.com,DIRECT'
    - 'DOMAIN-SUFFIX,office365.com,DIRECT'
    - 'DOMAIN-KEYWORD,officecdn,DIRECT'
    - 'DOMAIN-SUFFIX,oschina.net,DIRECT'
    - 'DOMAIN-SUFFIX,ppsimg.com,DIRECT'
    - 'DOMAIN-SUFFIX,pstatp.com,DIRECT'
    - 'DOMAIN-SUFFIX,qcloud.com,DIRECT'
    - 'DOMAIN-SUFFIX,qdaily.com,DIRECT'
    - 'DOMAIN-SUFFIX,qdmm.com,DIRECT'
    - 'DOMAIN-SUFFIX,qhimg.com,DIRECT'
    - 'DOMAIN-SUFFIX,qhres.com,DIRECT'
    - 'DOMAIN-SUFFIX,qidian.com,DIRECT'
    - 'DOMAIN-SUFFIX,qihucdn.com,DIRECT'
    - 'DOMAIN-SUFFIX,qiniu.com,DIRECT'
    - 'DOMAIN-SUFFIX,qiniucdn.com,DIRECT'
    - 'DOMAIN-SUFFIX,qiyipic.com,DIRECT'
    - 'DOMAIN-SUFFIX,qq.com,DIRECT'
    - 'DOMAIN-SUFFIX,qqurl.com,DIRECT'
    - 'DOMAIN-SUFFIX,rarbg.to,DIRECT'
    - 'DOMAIN-SUFFIX,ruguoapp.com,DIRECT'
    - 'DOMAIN-SUFFIX,segmentfault.com,DIRECT'
    - 'DOMAIN-SUFFIX,sinaapp.com,DIRECT'
    - 'DOMAIN-SUFFIX,smzdm.com,DIRECT'
    - 'DOMAIN-SUFFIX,snapdrop.net,DIRECT'
    - 'DOMAIN-SUFFIX,sogou.com,DIRECT'
    - 'DOMAIN-SUFFIX,sogoucdn.com,DIRECT'
    - 'DOMAIN-SUFFIX,sohu.com,DIRECT'
    - 'DOMAIN-SUFFIX,soku.com,DIRECT'
    - 'DOMAIN-SUFFIX,speedtest.net,DIRECT'
    - 'DOMAIN-SUFFIX,sspai.com,DIRECT'
    - 'DOMAIN-SUFFIX,suning.com,DIRECT'
    - 'DOMAIN-SUFFIX,taobao.com,DIRECT'
    - 'DOMAIN-SUFFIX,tencent.com,DIRECT'
    - 'DOMAIN-SUFFIX,tenpay.com,DIRECT'
    - 'DOMAIN-SUFFIX,tianyancha.com,DIRECT'
    - 'DOMAIN-SUFFIX,tmall.com,DIRECT'
    - 'DOMAIN-SUFFIX,tudou.com,DIRECT'
    - 'DOMAIN-SUFFIX,umetrip.com,DIRECT'
    - 'DOMAIN-SUFFIX,upaiyun.com,DIRECT'
    - 'DOMAIN-SUFFIX,upyun.com,DIRECT'
    - 'DOMAIN-SUFFIX,veryzhun.com,DIRECT'
    - 'DOMAIN-SUFFIX,weather.com,DIRECT'
    - 'DOMAIN-SUFFIX,weibo.com,DIRECT'
    - 'DOMAIN-SUFFIX,xiami.com,DIRECT'
    - 'DOMAIN-SUFFIX,xiami.net,DIRECT'
    - 'DOMAIN-SUFFIX,xiaomicp.com,DIRECT'
    - 'DOMAIN-SUFFIX,ximalaya.com,DIRECT'
    - 'DOMAIN-SUFFIX,xmcdn.com,DIRECT'
    - 'DOMAIN-SUFFIX,xunlei.com,DIRECT'
    - 'DOMAIN-SUFFIX,yhd.com,DIRECT'
    - 'DOMAIN-SUFFIX,yihaodianimg.com,DIRECT'
    - 'DOMAIN-SUFFIX,yinxiang.com,DIRECT'
    - 'DOMAIN-SUFFIX,ykimg.com,DIRECT'
    - 'DOMAIN-SUFFIX,youdao.com,DIRECT'
    - 'DOMAIN-SUFFIX,youku.com,DIRECT'
    - 'DOMAIN-SUFFIX,zealer.com,DIRECT'
    - 'DOMAIN-SUFFIX,zhihu.com,DIRECT'
    - 'DOMAIN-SUFFIX,zhimg.com,DIRECT'
    - 'DOMAIN-SUFFIX,zimuzu.tv,DIRECT'
    - 'DOMAIN-SUFFIX,zoho.com,DIRECT'
    - 'DOMAIN-KEYWORD,amazon,天路云'
    - 'DOMAIN-KEYWORD,google,天路云'
    - 'DOMAIN-KEYWORD,gmail,天路云'
    - 'DOMAIN-KEYWORD,youtube,天路云'
    - 'DOMAIN-KEYWORD,facebook,天路云'
    - 'DOMAIN-SUFFIX,fb.me,天路云'
    - 'DOMAIN-SUFFIX,fbcdn.net,天路云'
    - 'DOMAIN-KEYWORD,twitter,天路云'
    - 'DOMAIN-KEYWORD,instagram,天路云'
    - 'DOMAIN-KEYWORD,dropbox,天路云'
    - 'DOMAIN-SUFFIX,twimg.com,天路云'
    - 'DOMAIN-KEYWORD,blogspot,天路云'
    - 'DOMAIN-SUFFIX,youtu.be,天路云'
    - 'DOMAIN-KEYWORD,whatsapp,天路云'
    - 'DOMAIN-KEYWORD,admarvel,REJECT'
    - 'DOMAIN-KEYWORD,admaster,REJECT'
    - 'DOMAIN-KEYWORD,adsage,REJECT'
    - 'DOMAIN-KEYWORD,adsmogo,REJECT'
    - 'DOMAIN-KEYWORD,adsrvmedia,REJECT'
    - 'DOMAIN-KEYWORD,adwords,REJECT'
    - 'DOMAIN-KEYWORD,adservice,REJECT'
    - 'DOMAIN-SUFFIX,appsflyer.com,REJECT'
    - 'DOMAIN-KEYWORD,domob,REJECT'
    - 'DOMAIN-SUFFIX,doubleclick.net,REJECT'
    - 'DOMAIN-KEYWORD,duomeng,REJECT'
    - 'DOMAIN-KEYWORD,dwtrack,REJECT'
    - 'DOMAIN-KEYWORD,guanggao,REJECT'
    - 'DOMAIN-KEYWORD,lianmeng,REJECT'
    - 'DOMAIN-SUFFIX,mmstat.com,REJECT'
    - 'DOMAIN-KEYWORD,mopub,REJECT'
    - 'DOMAIN-KEYWORD,omgmta,REJECT'
    - 'DOMAIN-KEYWORD,openx,REJECT'
    - 'DOMAIN-KEYWORD,partnerad,REJECT'
    - 'DOMAIN-KEYWORD,pingfore,REJECT'
    - 'DOMAIN-KEYWORD,supersonicads,REJECT'
    - 'DOMAIN-KEYWORD,uedas,REJECT'
    - 'DOMAIN-KEYWORD,umeng,REJECT'
    - 'DOMAIN-KEYWORD,usage,REJECT'
    - 'DOMAIN-SUFFIX,vungle.com,REJECT'
    - 'DOMAIN-KEYWORD,wlmonitor,REJECT'
    - 'DOMAIN-KEYWORD,zjtoolbar,REJECT'
    - 'DOMAIN-SUFFIX,9to5mac.com,天路云'
    - 'DOMAIN-SUFFIX,abpchina.org,天路云'
    - 'DOMAIN-SUFFIX,adblockplus.org,天路云'
    - 'DOMAIN-SUFFIX,adobe.com,天路云'
    - 'DOMAIN-SUFFIX,akamaized.net,天路云'
    - 'DOMAIN-SUFFIX,alfredapp.com,天路云'
    - 'DOMAIN-SUFFIX,amplitude.com,天路云'
    - 'DOMAIN-SUFFIX,ampproject.org,天路云'
    - 'DOMAIN-SUFFIX,android.com,天路云'
    - 'DOMAIN-SUFFIX,angularjs.org,天路云'
    - 'DOMAIN-SUFFIX,aolcdn.com,天路云'
    - 'DOMAIN-SUFFIX,apkpure.com,天路云'
    - 'DOMAIN-SUFFIX,appledaily.com,天路云'
    - 'DOMAIN-SUFFIX,appshopper.com,天路云'
    - 'DOMAIN-SUFFIX,appspot.com,天路云'
    - 'DOMAIN-SUFFIX,arcgis.com,天路云'
    - 'DOMAIN-SUFFIX,archive.org,天路云'
    - 'DOMAIN-SUFFIX,armorgames.com,天路云'
    - 'DOMAIN-SUFFIX,aspnetcdn.com,天路云'
    - 'DOMAIN-SUFFIX,att.com,天路云'
    - 'DOMAIN-SUFFIX,awsstatic.com,天路云'
    - 'DOMAIN-SUFFIX,azureedge.net,天路云'
    - 'DOMAIN-SUFFIX,azurewebsites.net,天路云'
    - 'DOMAIN-SUFFIX,bing.com,天路云'
    - 'DOMAIN-SUFFIX,bintray.com,天路云'
    - 'DOMAIN-SUFFIX,bit.com,天路云'
    - 'DOMAIN-SUFFIX,bit.ly,天路云'
    - 'DOMAIN-SUFFIX,bitbucket.org,天路云'
    - 'DOMAIN-SUFFIX,bjango.com,天路云'
    - 'DOMAIN-SUFFIX,bkrtx.com,天路云'
    - 'DOMAIN-SUFFIX,blog.com,天路云'
    - 'DOMAIN-SUFFIX,blogcdn.com,天路云'
    - 'DOMAIN-SUFFIX,blogger.com,天路云'
    - 'DOMAIN-SUFFIX,blogsmithmedia.com,天路云'
    - 'DOMAIN-SUFFIX,blogspot.com,天路云'
    - 'DOMAIN-SUFFIX,blogspot.hk,天路云'
    - 'DOMAIN-SUFFIX,bloomberg.com,天路云'
    - 'DOMAIN-SUFFIX,box.com,天路云'
    - 'DOMAIN-SUFFIX,box.net,天路云'
    - 'DOMAIN-SUFFIX,cachefly.net,天路云'
    - 'DOMAIN-SUFFIX,chromium.org,天路云'
    - 'DOMAIN-SUFFIX,cl.ly,天路云'
    - 'DOMAIN-SUFFIX,cloudflare.com,天路云'
    - 'DOMAIN-SUFFIX,cloudfront.net,天路云'
    - 'DOMAIN-SUFFIX,cloudmagic.com,天路云'
    - 'DOMAIN-SUFFIX,cmail19.com,天路云'
    - 'DOMAIN-SUFFIX,cnet.com,天路云'
    - 'DOMAIN-SUFFIX,cocoapods.org,天路云'
    - 'DOMAIN-SUFFIX,comodoca.com,天路云'
    - 'DOMAIN-SUFFIX,crashlytics.com,天路云'
    - 'DOMAIN-SUFFIX,culturedcode.com,天路云'
    - 'DOMAIN-SUFFIX,d.pr,天路云'
    - 'DOMAIN-SUFFIX,danilo.to,天路云'
    - 'DOMAIN-SUFFIX,dayone.me,天路云'
    - 'DOMAIN-SUFFIX,db.tt,天路云'
    - 'DOMAIN-SUFFIX,deskconnect.com,天路云'
    - 'DOMAIN-SUFFIX,disq.us,天路云'
    - 'DOMAIN-SUFFIX,disqus.com,天路云'
    - 'DOMAIN-SUFFIX,disquscdn.com,天路云'
    - 'DOMAIN-SUFFIX,dnsimple.com,天路云'
    - 'DOMAIN-SUFFIX,docker.com,天路云'
    - 'DOMAIN-SUFFIX,dribbble.com,天路云'
    - 'DOMAIN-SUFFIX,droplr.com,天路云'
    - 'DOMAIN-SUFFIX,duckduckgo.com,天路云'
    - 'DOMAIN-SUFFIX,dueapp.com,天路云'
    - 'DOMAIN-SUFFIX,dytt8.net,天路云'
    - 'DOMAIN-SUFFIX,edgecastcdn.net,天路云'
    - 'DOMAIN-SUFFIX,edgekey.net,天路云'
    - 'DOMAIN-SUFFIX,edgesuite.net,天路云'
    - 'DOMAIN-SUFFIX,engadget.com,天路云'
    - 'DOMAIN-SUFFIX,entrust.net,天路云'
    - 'DOMAIN-SUFFIX,eurekavpt.com,天路云'
    - 'DOMAIN-SUFFIX,evernote.com,天路云'
    - 'DOMAIN-SUFFIX,fabric.io,天路云'
    - 'DOMAIN-SUFFIX,fast.com,天路云'
    - 'DOMAIN-SUFFIX,fastly.net,天路云'
    - 'DOMAIN-SUFFIX,fc2.com,天路云'
    - 'DOMAIN-SUFFIX,feedburner.com,天路云'
    - 'DOMAIN-SUFFIX,feedly.com,天路云'
    - 'DOMAIN-SUFFIX,feedsportal.com,天路云'
    - 'DOMAIN-SUFFIX,fiftythree.com,天路云'
    - 'DOMAIN-SUFFIX,firebaseio.com,天路云'
    - 'DOMAIN-SUFFIX,flexibits.com,天路云'
    - 'DOMAIN-SUFFIX,flickr.com,天路云'
    - 'DOMAIN-SUFFIX,flipboard.com,天路云'
    - 'DOMAIN-SUFFIX,g.co,天路云'
    - 'DOMAIN-SUFFIX,gabia.net,天路云'
    - 'DOMAIN-SUFFIX,geni.us,天路云'
    - 'DOMAIN-SUFFIX,gfx.ms,天路云'
    - 'DOMAIN-SUFFIX,ggpht.com,天路云'
    - 'DOMAIN-SUFFIX,ghostnoteapp.com,天路云'
    - 'DOMAIN-SUFFIX,git.io,天路云'
    - 'DOMAIN-KEYWORD,github,天路云'
    - 'DOMAIN-SUFFIX,globalsign.com,天路云'
    - 'DOMAIN-SUFFIX,gmodules.com,天路云'
    - 'DOMAIN-SUFFIX,godaddy.com,天路云'
    - 'DOMAIN-SUFFIX,golang.org,天路云'
    - 'DOMAIN-SUFFIX,gongm.in,天路云'
    - 'DOMAIN-SUFFIX,goo.gl,天路云'
    - 'DOMAIN-SUFFIX,goodreaders.com,天路云'
    - 'DOMAIN-SUFFIX,goodreads.com,天路云'
    - 'DOMAIN-SUFFIX,gravatar.com,天路云'
    - 'DOMAIN-SUFFIX,gstatic.com,天路云'
    - 'DOMAIN-SUFFIX,gvt0.com,天路云'
    - 'DOMAIN-SUFFIX,hockeyapp.net,天路云'
    - 'DOMAIN-SUFFIX,hotmail.com,天路云'
    - 'DOMAIN-SUFFIX,icons8.com,天路云'
    - 'DOMAIN-SUFFIX,ifixit.com,天路云'
    - 'DOMAIN-SUFFIX,ift.tt,天路云'
    - 'DOMAIN-SUFFIX,ifttt.com,天路云'
    - 'DOMAIN-SUFFIX,iherb.com,天路云'
    - 'DOMAIN-SUFFIX,imageshack.us,天路云'
    - 'DOMAIN-SUFFIX,img.ly,天路云'
    - 'DOMAIN-SUFFIX,imgur.com,天路云'
    - 'DOMAIN-SUFFIX,imore.com,天路云'
    - 'DOMAIN-SUFFIX,instapaper.com,天路云'
    - 'DOMAIN-SUFFIX,ipn.li,天路云'
    - 'DOMAIN-SUFFIX,is.gd,天路云'
    - 'DOMAIN-SUFFIX,issuu.com,天路云'
    - 'DOMAIN-SUFFIX,itgonglun.com,天路云'
    - 'DOMAIN-SUFFIX,itun.es,天路云'
    - 'DOMAIN-SUFFIX,ixquick.com,天路云'
    - 'DOMAIN-SUFFIX,j.mp,天路云'
    - 'DOMAIN-SUFFIX,js.revsci.net,天路云'
    - 'DOMAIN-SUFFIX,jshint.com,天路云'
    - 'DOMAIN-SUFFIX,jtvnw.net,天路云'
    - 'DOMAIN-SUFFIX,justgetflux.com,天路云'
    - 'DOMAIN-SUFFIX,kat.cr,天路云'
    - 'DOMAIN-SUFFIX,klip.me,天路云'
    - 'DOMAIN-SUFFIX,libsyn.com,天路云'
    - 'DOMAIN-SUFFIX,linkedin.com,天路云'
    - 'DOMAIN-SUFFIX,line-apps.com,天路云'
    - 'DOMAIN-SUFFIX,linode.com,天路云'
    - 'DOMAIN-SUFFIX,lithium.com,天路云'
    - 'DOMAIN-SUFFIX,littlehj.com,天路云'
    - 'DOMAIN-SUFFIX,live.com,天路云'
    - 'DOMAIN-SUFFIX,live.net,天路云'
    - 'DOMAIN-SUFFIX,livefilestore.com,天路云'
    - 'DOMAIN-SUFFIX,llnwd.net,天路云'
    - 'DOMAIN-SUFFIX,macid.co,天路云'
    - 'DOMAIN-SUFFIX,macromedia.com,天路云'
    - 'DOMAIN-SUFFIX,macrumors.com,天路云'
    - 'DOMAIN-SUFFIX,mashable.com,天路云'
    - 'DOMAIN-SUFFIX,mathjax.org,天路云'
    - 'DOMAIN-SUFFIX,medium.com,天路云'
    - 'DOMAIN-SUFFIX,mega.co.nz,天路云'
    - 'DOMAIN-SUFFIX,mega.nz,天路云'
    - 'DOMAIN-SUFFIX,megaupload.com,天路云'
    - 'DOMAIN-SUFFIX,microsofttranslator.com,天路云'
    - 'DOMAIN-SUFFIX,mindnode.com,天路云'
    - 'DOMAIN-SUFFIX,mobile01.com,天路云'
    - 'DOMAIN-SUFFIX,modmyi.com,天路云'
    - 'DOMAIN-SUFFIX,msedge.net,天路云'
    - 'DOMAIN-SUFFIX,myfontastic.com,天路云'
    - 'DOMAIN-SUFFIX,name.com,天路云'
    - 'DOMAIN-SUFFIX,nextmedia.com,天路云'
    - 'DOMAIN-SUFFIX,nsstatic.net,天路云'
    - 'DOMAIN-SUFFIX,nssurge.com,天路云'
    - 'DOMAIN-SUFFIX,nyt.com,天路云'
    - 'DOMAIN-SUFFIX,nytimes.com,天路云'
    - 'DOMAIN-SUFFIX,omnigroup.com,天路云'
    - 'DOMAIN-SUFFIX,onedrive.com,天路云'
    - 'DOMAIN-SUFFIX,onenote.com,天路云'
    - 'DOMAIN-SUFFIX,ooyala.com,天路云'
    - 'DOMAIN-SUFFIX,openvpn.net,天路云'
    - 'DOMAIN-SUFFIX,openwrt.org,天路云'
    - 'DOMAIN-SUFFIX,orkut.com,天路云'
    - 'DOMAIN-SUFFIX,osxdaily.com,天路云'
    - 'DOMAIN-SUFFIX,outlook.com,天路云'
    - 'DOMAIN-SUFFIX,ow.ly,天路云'
    - 'DOMAIN-SUFFIX,paddleapi.com,天路云'
    - 'DOMAIN-SUFFIX,parallels.com,天路云'
    - 'DOMAIN-SUFFIX,parse.com,天路云'
    - 'DOMAIN-SUFFIX,pdfexpert.com,天路云'
    - 'DOMAIN-SUFFIX,periscope.tv,天路云'
    - 'DOMAIN-SUFFIX,pinboard.in,天路云'
    - 'DOMAIN-SUFFIX,pinterest.com,天路云'
    - 'DOMAIN-SUFFIX,pixelmator.com,天路云'
    - 'DOMAIN-SUFFIX,pixiv.net,天路云'
    - 'DOMAIN-SUFFIX,playpcesor.com,天路云'
    - 'DOMAIN-SUFFIX,playstation.com,天路云'
    - 'DOMAIN-SUFFIX,playstation.com.hk,天路云'
    - 'DOMAIN-SUFFIX,playstation.net,天路云'
    - 'DOMAIN-SUFFIX,playstationnetwork.com,天路云'
    - 'DOMAIN-SUFFIX,pushwoosh.com,天路云'
    - 'DOMAIN-SUFFIX,rime.im,天路云'
    - 'DOMAIN-SUFFIX,servebom.com,天路云'
    - 'DOMAIN-SUFFIX,sfx.ms,天路云'
    - 'DOMAIN-SUFFIX,shadowsocks.org,天路云'
    - 'DOMAIN-SUFFIX,sharethis.com,天路云'
    - 'DOMAIN-SUFFIX,shazam.com,天路云'
    - 'DOMAIN-SUFFIX,skype.com,天路云'
    - 'DOMAIN-SUFFIX,smartdns天路云.com,天路云'
    - 'DOMAIN-SUFFIX,smartmailcloud.com,天路云'
    - 'DOMAIN-SUFFIX,sndcdn.com,天路云'
    - 'DOMAIN-SUFFIX,sony.com,天路云'
    - 'DOMAIN-SUFFIX,soundcloud.com,天路云'
    - 'DOMAIN-SUFFIX,sourceforge.net,天路云'
    - 'DOMAIN-SUFFIX,spotify.com,天路云'
    - 'DOMAIN-SUFFIX,squarespace.com,天路云'
    - 'DOMAIN-SUFFIX,sstatic.net,天路云'
    - 'DOMAIN-SUFFIX,st.luluku.pw,天路云'
    - 'DOMAIN-SUFFIX,stackoverflow.com,天路云'
    - 'DOMAIN-SUFFIX,startpage.com,天路云'
    - 'DOMAIN-SUFFIX,staticflickr.com,天路云'
    - 'DOMAIN-SUFFIX,steamcommunity.com,天路云'
    - 'DOMAIN-SUFFIX,symauth.com,天路云'
    - 'DOMAIN-SUFFIX,symcb.com,天路云'
    - 'DOMAIN-SUFFIX,symcd.com,天路云'
    - 'DOMAIN-SUFFIX,tapbots.com,天路云'
    - 'DOMAIN-SUFFIX,tapbots.net,天路云'
    - 'DOMAIN-SUFFIX,tdesktop.com,天路云'
    - 'DOMAIN-SUFFIX,techcrunch.com,天路云'
    - 'DOMAIN-SUFFIX,techsmith.com,天路云'
    - 'DOMAIN-SUFFIX,thepiratebay.org,天路云'
    - 'DOMAIN-SUFFIX,theverge.com,天路云'
    - 'DOMAIN-SUFFIX,time.com,天路云'
    - 'DOMAIN-SUFFIX,timeinc.net,天路云'
    - 'DOMAIN-SUFFIX,tiny.cc,天路云'
    - 'DOMAIN-SUFFIX,tinypic.com,天路云'
    - 'DOMAIN-SUFFIX,tmblr.co,天路云'
    - 'DOMAIN-SUFFIX,todoist.com,天路云'
    - 'DOMAIN-SUFFIX,trello.com,天路云'
    - 'DOMAIN-SUFFIX,trustasiassl.com,天路云'
    - 'DOMAIN-SUFFIX,tumblr.co,天路云'
    - 'DOMAIN-SUFFIX,tumblr.com,天路云'
    - 'DOMAIN-SUFFIX,tweetdeck.com,天路云'
    - 'DOMAIN-SUFFIX,tweetmarker.net,天路云'
    - 'DOMAIN-SUFFIX,twitch.tv,天路云'
    - 'DOMAIN-SUFFIX,txmblr.com,天路云'
    - 'DOMAIN-SUFFIX,typekit.net,天路云'
    - 'DOMAIN-SUFFIX,ubertags.com,天路云'
    - 'DOMAIN-SUFFIX,ublock.org,天路云'
    - 'DOMAIN-SUFFIX,ubnt.com,天路云'
    - 'DOMAIN-SUFFIX,ulyssesapp.com,天路云'
    - 'DOMAIN-SUFFIX,urchin.com,天路云'
    - 'DOMAIN-SUFFIX,usertrust.com,天路云'
    - 'DOMAIN-SUFFIX,v.gd,天路云'
    - 'DOMAIN-SUFFIX,v2ex.com,天路云'
    - 'DOMAIN-SUFFIX,vimeo.com,天路云'
    - 'DOMAIN-SUFFIX,vimeocdn.com,天路云'
    - 'DOMAIN-SUFFIX,vine.co,天路云'
    - 'DOMAIN-SUFFIX,vivaldi.com,天路云'
    - 'DOMAIN-SUFFIX,vox-cdn.com,天路云'
    - 'DOMAIN-SUFFIX,vsco.co,天路云'
    - 'DOMAIN-SUFFIX,vultr.com,天路云'
    - 'DOMAIN-SUFFIX,w.org,天路云'
    - 'DOMAIN-SUFFIX,w3schools.com,天路云'
    - 'DOMAIN-SUFFIX,webtype.com,天路云'
    - 'DOMAIN-SUFFIX,wikiwand.com,天路云'
    - 'DOMAIN-SUFFIX,wikileaks.org,天路云'
    - 'DOMAIN-SUFFIX,wikimedia.org,天路云'
    - 'DOMAIN-SUFFIX,wikipedia.com,天路云'
    - 'DOMAIN-SUFFIX,wikipedia.org,天路云'
    - 'DOMAIN-SUFFIX,windows.com,天路云'
    - 'DOMAIN-SUFFIX,windows.net,天路云'
    - 'DOMAIN-SUFFIX,wire.com,天路云'
    - 'DOMAIN-SUFFIX,wordpress.com,天路云'
    - 'DOMAIN-SUFFIX,workflowy.com,天路云'
    - 'DOMAIN-SUFFIX,wp.com,天路云'
    - 'DOMAIN-SUFFIX,wsj.com,天路云'
    - 'DOMAIN-SUFFIX,wsj.net,天路云'
    - 'DOMAIN-SUFFIX,xda-developers.com,天路云'
    - 'DOMAIN-SUFFIX,xeeno.com,天路云'
    - 'DOMAIN-SUFFIX,xiti.com,天路云'
    - 'DOMAIN-SUFFIX,yahoo.com,天路云'
    - 'DOMAIN-SUFFIX,yimg.com,天路云'
    - 'DOMAIN-SUFFIX,ying.com,天路云'
    - 'DOMAIN-SUFFIX,yoyo.org,天路云'
    - 'DOMAIN-SUFFIX,ytimg.com,天路云'
    - 'DOMAIN-SUFFIX,telegra.ph,天路云'
    - 'DOMAIN-SUFFIX,telegram.org,天路云'
    - 'IP-CIDR,91.108.4.0/22,天路云,no-resolve'
    - 'IP-CIDR,91.108.8.0/21,天路云,no-resolve'
    - 'IP-CIDR,91.108.16.0/22,天路云,no-resolve'
    - 'IP-CIDR,91.108.56.0/22,天路云,no-resolve'
    - 'IP-CIDR,149.154.160.0/20,天路云,no-resolve'
    - 'IP-CIDR6,2001:67c:4e8::/48,天路云,no-resolve'
    - 'IP-CIDR6,2001:b28:f23d::/48,天路云,no-resolve'
    - 'IP-CIDR6,2001:b28:f23f::/48,天路云,no-resolve'
    - 'IP-CIDR,120.232.181.162/32,天路云,no-resolve'
    - 'IP-CIDR,120.241.147.226/32,天路云,no-resolve'
    - 'IP-CIDR,120.253.253.226/32,天路云,no-resolve'
    - 'IP-CIDR,120.253.255.162/32,天路云,no-resolve'
    - 'IP-CIDR,120.253.255.34/32,天路云,no-resolve'
    - 'IP-CIDR,120.253.255.98/32,天路云,no-resolve'
    - 'IP-CIDR,180.163.150.162/32,天路云,no-resolve'
    - 'IP-CIDR,180.163.150.34/32,天路云,no-resolve'
    - 'IP-CIDR,180.163.151.162/32,天路云,no-resolve'
    - 'IP-CIDR,180.163.151.34/32,天路云,no-resolve'
    - 'IP-CIDR,203.208.39.0/24,天路云,no-resolve'
    - 'IP-CIDR,203.208.40.0/24,天路云,no-resolve'
    - 'IP-CIDR,203.208.41.0/24,天路云,no-resolve'
    - 'IP-CIDR,203.208.43.0/24,天路云,no-resolve'
    - 'IP-CIDR,203.208.50.0/24,天路云,no-resolve'
    - 'IP-CIDR,220.181.174.162/32,天路云,no-resolve'
    - 'IP-CIDR,220.181.174.226/32,天路云,no-resolve'
    - 'IP-CIDR,220.181.174.34/32,天路云,no-resolve'
    - 'DOMAIN,injections.adguard.org,DIRECT'
    - 'DOMAIN,local.adguard.org,DIRECT'
    - 'DOMAIN-SUFFIX,local,DIRECT'
    - 'IP-CIDR,127.0.0.0/8,DIRECT'
    - 'IP-CIDR,172.16.0.0/12,DIRECT'
    - 'IP-CIDR,192.168.0.0/16,DIRECT'
    - 'IP-CIDR,10.0.0.0/8,DIRECT'
    - 'IP-CIDR,17.0.0.0/8,DIRECT'
    - 'IP-CIDR,100.64.0.0/10,DIRECT'
    - 'IP-CIDR,224.0.0.0/4,DIRECT'
    - 'IP-CIDR6,fe80::/10,DIRECT'
    - 'DOMAIN-SUFFIX,cn,DIRECT'
    - 'DOMAIN-KEYWORD,-cn,DIRECT'
    - 'GEOIP,CN,DIRECT'
    - 'MATCH,天路云'
]]

    -- Generate proxies list (replace ${proxies_list})
    local proxies_list_str = ""
    local proxy_names_list_str = ""
    for i, proxy in ipairs(proxies) do
        proxies_list_str = proxies_list_str .. string.format(
            "    - { name: %s, type: ss, server: %s, port: %d, cipher: %s, password: %s, udp: true }",
            string.format("%q", proxy.name),  -- Escape quotes
            string.format("%q", proxy.server),
            proxy.port,
            string.format("%q", proxy.method),
            string.format("%q", proxy.password)
        ) .. "\n"
        if i > 1 then
            proxy_names_list_str = proxy_names_list_str .. ", "
        end
        proxy_names_list_str = proxy_names_list_str .. string.format("%q", proxy.name)
    end

    -- Replace placeholders (Lua 5.1 compatible)
    local final_yaml = string.gsub(yaml_template, "${proxies_list}", proxies_list_str)
    final_yaml = string.gsub(final_yaml, "${proxy_names_list}", proxy_names_list_str)

    -- Write to output file
    local file = io.open(output_yaml, "w")
    if not file then
        log("ERROR", "Failed to write YAML file: " .. output_yaml)
        return false
    end
    file:write(final_yaml)
    file:close()

    log("INFO", "Final YAML generated: " .. output_yaml .. " (size: " .. #final_yaml .. " bytes)")
    return true
end

-- ===================== Main Process ======================
local function main()
    -- Get command line arguments (from shell script)
    local temp_file = arg[1]
    local output_yaml = arg[2]

    -- Check arguments
    if not temp_file or not output_yaml then
        log("ERROR", "Usage: lua clash-parser.lua <temp_file> <output_yaml>")
        os.exit(1)
    end

    log("INFO", "Starting Clash subscription parser (Lua 5.1)")
    
    -- 1. Read subscription from temp file (downloaded by shell)
    local subscribe_base64 = read_subscription(temp_file)
    if not subscribe_base64 then
        log("ERROR", "Failed to read subscription file")
        os.exit(1)
    end

    -- 2. Base64 decode subscription content
    local decoded_content = base64_decode(subscribe_base64)
    if not decoded_content then
        log("ERROR", "Base64 decoding failed")
        os.exit(1)
    end

    -- 3. Parse ss:// nodes
    local proxies = parse_ss_links(decoded_content)
    if #proxies == 0 then
        log("ERROR", "No valid nodes parsed")
        os.exit(1)
    end

    -- 4. Generate YAML
    local ok = generate_final_yaml(proxies, output_yaml)
    if not ok then
        os.exit(1)
    end

    log("INFO", "Parser executed successfully!")
    os.exit(0)
end

-- Start main process
main()
