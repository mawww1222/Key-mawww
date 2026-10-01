# Mawww Key System

Generated-key and public validation API untuk Mawww Hub. Project ini dibuat untuk dipasang di GitHub lalu dideploy ke Railway.

## Fitur

- Public key checker di `/`
- Developer login di `/dev/login`
- Developer dashboard di `/dev`
- Generate 1–100 key sekaligus
- Prefix custom
- Expiration dalam hari atau unlimited
- Maximum uses atau unlimited
- Revoke / activate key
- PostgreSQL persistence
- Public JSON API: `/api/validate`, `/api/status`
- Health check: `/health`
- Password admin tidak disimpan di source code

## Railway

1. Push file project ini ke repository `mawww1222/Key-mawww`.
2. Railway -> New Project -> Deploy from GitHub Repo -> pilih repository.
3. Tambahkan PostgreSQL ke project.
4. Pada service aplikasi, set Variables:

```text
DATABASE_URL=${{Postgres.DATABASE_URL}}
KEY_ADMIN_USER=mawwwhub
KEY_ADMIN_PASSWORD=GANTI_DENGAN_PASSWORD_KAMU
KEY_SESSION_SECRET=STRING_ACAK_MINIMAL_32_KARAKTER
KEY_APP_NAME=Mawww Hub
KEY_PREFIX=MAWWW
NODE_ENV=production
```

5. Generate Public Domain pada service aplikasi.

Railway menyediakan `DATABASE_URL` pada service PostgreSQL, dan reference variable seperti `${{Postgres.DATABASE_URL}}` dapat dipakai oleh service aplikasi. Lihat dokumentasi Railway untuk PostgreSQL dan variables.

## URLs

- Public: `https://DOMAIN/`
- Developer: `https://DOMAIN/dev`
- Developer login: `https://DOMAIN/dev/login`
- API index: `https://DOMAIN/api`
- Health: `https://DOMAIN/health`

## API untuk script

```text
GET https://DOMAIN/api/validate?key=YOUR_KEY&product=Mawww%20Hub
```

Valid key mengembalikan:

```json
{
  "ok": true,
  "valid": true,
  "key": "MAWWW-ABC123-DEF456-GHI789",
  "product": "Mawww Hub",
  "expires_at": null,
  "uses": 1,
  "max_uses": 1
}
```

Status key tanpa melakukan validation-use:

```text
GET https://DOMAIN/api/status?key=YOUR_KEY
```

## Contoh Lua

Ganti `DOMAIN` dan `YOUR_KEY`.

```lua
local HttpService = game:GetService("HttpService")
local API = "https://DOMAIN/api/validate"
local KEY = "MAWWW-PASTE-YOUR-KEY"

local ok, body = pcall(function()
    return game:HttpGet(
        API .. "?key=" .. HttpService:UrlEncode(KEY)
            .. "&product=" .. HttpService:UrlEncode("Mawww Hub")
    )
end)

if not ok then
    warn("Key API request failed")
    return
end

local data = HttpService:JSONDecode(body)

if data.valid == true then
    print("KEY VALID")
    -- jalankan script Mawww Hub di sini
else
    warn("KEY INVALID:", data.reason or data.error)
end
```

Catatan: kemampuan HTTP pada Lua tergantung environment Roblox/executor yang digunakan. Server ini hanya menyediakan endpoint HTTP/JSON.
