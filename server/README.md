# PharmaDesk Server — setup guide

This is the server every branch/device connects to. Once it's running, PharmaDesk
stops storing business data on individual devices — it all lives here.

## 1. Important: you need a host with a *persistent disk*

This server saves data as JSON files on disk. Some free hosting tiers (including
Render's free web service tier) **wipe the filesystem on every restart or
redeploy** — if you use one of those, your data would silently disappear the
next time the server restarts. Before you pick a host, confirm it gives you a
persistent disk/volume that survives restarts. Options that work:

- **Render** — free web service *plus* a small paid "Persistent Disk" add-on
  (a few dollars/month). Without the disk add-on, don't use Render for this.
- **Railway** — supports persistent volumes on paid plans.
- **A small VPS** (DigitalOcean, Linode, Hetzner, a home server) — the disk is
  yours permanently by default; this is the simplest option to reason about.
- **Fly.io** — supports persistent volumes.

If you're not sure which to pick, a small VPS (~$5/month) with Node.js
installed is the least confusing option — there's no separate "disk add-on"
to remember to attach.

## 2. Install and configure

```bash
cd server
npm install
```

Set these environment variables on your host before starting:

| Variable | Required | What it's for |
|---|---|---|
| `APP_API_KEY` | Yes | A shared secret the app sends on every request. Generate one: `node -e "console.log(require('crypto').randomBytes(24).toString('hex'))"` |
| `JWT_SECRET` | Yes | Signs login sessions. Generate the same way, as a **different** value. |
| `ADMIN_USERNAME` | No (default `admin`) | Username for the first admin account. |
| `ADMIN_PASSWORD` | Only for first boot | Creates the first admin account. **Remove this env var after your first successful login** so it can't be replayed later. |
| `ALLOWED_ORIGIN` | Recommended | The exact URL your app is hosted at, e.g. `https://your-pharmacy.pages.dev`. Defaults to `*` (any site) if unset — fine for testing, not for production. |
| `PORT` | No | Defaults to 4000; most hosts set this automatically. |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM` | Only if you want emailed backups | Your email provider's SMTP details. |

Start it:

```bash
npm start
```

## 3. First login

1. With `ADMIN_PASSWORD` set, start the server once — it creates one admin
   account (`ADMIN_USERNAME` / `ADMIN_PASSWORD`).
2. In the PharmaDesk app, go to **Settings → Cloud Sync**, enter your
   server's URL and the `APP_API_KEY` you generated, and save.
3. Log in with the admin username/password at the login screen.
4. Go remove `ADMIN_PASSWORD` from your host's environment variables — it's
   no longer needed and shouldn't be left sitting there.
5. From **Settings → Staff**, create real accounts for everyone else. Each
   person gets their own username + password, set via the app (this calls
   `POST /api/auth/set-credentials` on the server) — the same login then
   works from any device, since the account lives on the server, not on
   any one phone or computer.

## 4. Backups

- **Manual download**: Settings → Data backup → this now downloads directly
  from the server (`GET /api/backup`), not from any device's local storage.
- **Automatic**: the server writes a full snapshot to `server/backups/`
  every 24 hours automatically, keeping the last 30 days. Make sure
  `server/backups/` is on the same persistent disk as `server/data/` — if
  you're using a VPS, that's automatic; on a platform with separate volume
  mounts, point both at the same persistent volume.
- **Emailed backups**: configure the `SMTP_*` environment variables, then
  use Settings → Data backup → "Email backup" in the app.

## 5. What this does and doesn't solve

- **Data stays on the server, not the device**: once Cloud Sync is
  configured, the app reads and writes directly to this server instead of
  the browser's local storage.
- **Same login everywhere**: accounts and passwords live here, so the same
  username/password works from any device.
- **Refreshing the tab won't log you out**: the app keeps a short-lived
  session token in the browser tab only for as long as that tab stays open,
  and re-validates it against this server (`GET /api/auth/me`) — refresh
  reuses it instead of asking you to log in again.
- **What it can't fully guarantee**: no web app can be made 100%
  tamper-proof against someone using their own browser's developer tools —
  that's a limitation of how browsers work, not specific to PharmaDesk. What
  this server does instead is check permissions independently on every
  request, so even a tampered client still can't do anything the server
  doesn't allow. Treat physical device security (who has access to a logged-in
  device) and account passwords as your other two real lines of defense.
