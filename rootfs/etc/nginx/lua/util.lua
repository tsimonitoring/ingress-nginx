local string_len = string.len
local string_sub = string.sub
local string_format = string.format

local _M = {}

function _M.get_nodes(endpoints)
  local nodes = {}
  local weight = 1

  for _, endpoint in pairs(endpoints) do
    local endpoint_string = endpoint.address .. ":" .. endpoint.port
    nodes[endpoint_string] = weight
  end

  return nodes
end

-- given an Nginx variable i.e $request_uri
-- it returns value of ngx.var[request_uri]
function _M.lua_ngx_var(ngx_var)
  local var_name = string_sub(ngx_var, 2)
  if var_name:match("^%d+$") then
    var_name = tonumber(var_name)
  end

  return ngx.var[var_name]
end

-- normalize_endpoints takes endpoints as an array of endpoint objects
-- and returns a table where keys are string that's endpoint.address .. ":" .. endpoint.port
-- and values are all true
local function normalize_endpoints(endpoints)
  local normalized_endpoints = {}

  for _, endpoint in pairs(endpoints) do
    local endpoint_string = string_format("%s:%s", endpoint.address, endpoint.port)
    normalized_endpoints[endpoint_string] = true
  end

  return normalized_endpoints
end

-- diff_endpoints compares old and new
-- and as a first argument returns what endpoints are in new
-- but are not in old, and as a second argument it returns
-- what endpoints are in old but are in new.
-- Both return values are normalized (ip:port).
function _M.diff_endpoints(old, new)
  local endpoints_added, endpoints_removed = {}, {}
  local normalized_old, normalized_new = normalize_endpoints(old), normalize_endpoints(new)

  for endpoint_string, _ in pairs(normalized_old) do
    if not normalized_new[endpoint_string] then
      table.insert(endpoints_removed, endpoint_string)
    end
  end

  for endpoint_string, _ in pairs(normalized_new) do
    if not normalized_old[endpoint_string] then
      table.insert(endpoints_added, endpoint_string)
    end
  end

  return endpoints_added, endpoints_removed
end

-- this implementation is taken from
-- https://web.archive.org/web/20131225070434/http://snippets.luacode.org/snippets/Deep_Comparison_of_Two_Values_3
-- and modified for use in this project
local function deep_compare(t1, t2, ignore_mt)
  local ty1 = type(t1)
  local ty2 = type(t2)
  if ty1 ~= ty2 then return false end
  -- non-table types can be directly compared
  if ty1 ~= 'table' and ty2 ~= 'table' then return t1 == t2 end
  -- as well as tables which have the metamethod __eq
  local mt = getmetatable(t1)
  if not ignore_mt and mt and mt.__eq then return t1 == t2 end
  for k1,v1 in pairs(t1) do
    local v2 = t2[k1]
    if v2 == nil or not deep_compare(v1,v2) then return false end
  end
  for k2,v2 in pairs(t2) do
    local v1 = t1[k2]
    if v1 == nil or not deep_compare(v1,v2) then return false end
  end
  return true
end
_M.deep_compare = deep_compare

function _M.is_blank(str)
  return str == nil or string_len(str) == 0
end

-- this implementation is taken from:
-- https://github.com/luafun/luafun/blob/master/fun.lua#L33
-- SHA: 04c99f9c393e54a604adde4b25b794f48104e0d0
local function deepcopy(orig)
  local orig_type = type(orig)
  local copy
  if orig_type == 'table' then
      copy = {}
      for orig_key, orig_value in next, orig, nil do
          copy[deepcopy(orig_key)] = deepcopy(orig_value)
      end
  else
      copy = orig
  end
  return copy
end
_M.deepcopy = deepcopy

local function tablelength(T)
  local count = 0
  for _ in pairs(T) do
      count = count + 1
  end
  return count
end
_M.tablelength = tablelength

-- replaces special character value a with value b for all occurences in a string
local function replace_special_char(str, a, b)
  return string.gsub(str, "%" .. a, b)
end
_M.replace_special_char = replace_special_char

return _M
