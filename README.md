# Parking Reservations (Google sign-in)

Reserve a parking slot for up to 3 hours. Users sign in with Google; overlaps are rejected by the server, and each user is limited to N reservations per day (default 1).

## 1. Create Google credentials (one time)
1. Go to https://console.cloud.google.com/ and create/select a project.
2. APIs & Services > OAuth consent screen: choose "Internal" (Google Workspace only) or "External", fill in the app name and your email, and save. For External apps in "Testing" mode, add your users under "Test users".
3. APIs & Services > Credentials > Create credentials > OAuth client ID > "Web application".
4. Under "Authorized redirect URIs" add: `http://localhost:3000/auth/google/callback`
   (for production use your real address, e.g. `https://parking.example.com/auth/google/callback`).
5. Copy the Client ID and Client secret.

## 2. Configure
Copy `.env.example` to `.env` and fill in the values:
- `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`: from step 1
- `SESSION_SECRET`: a long random string (the example file shows a command to generate one)
- `BASE_URL`: the public address of the site; it must match the redirect URI above
- `ALLOWED_DOMAIN` (optional): restrict sign-in to one email domain
- `MAX_RESERVATIONS_PER_DAY`: the per-user limit (default 1)

## 3. Run
Install Node.js 18+, open this folder in VS Code and run `npm start` (or press F5). Open http://localhost:3000.
No `npm install` is needed.

## Notes
- Never commit `.env` (it's in `.gitignore`).
- Sessions are signed cookies (HttpOnly, SameSite=Lax, 7 days). In production serve the site over HTTPS (`BASE_URL` starting with `https://` turns on the Secure flag).
- Reservations are stored in `data.json`. For heavier use, move to a database such as SQLite.
- Add slots by editing `SLOTS` in `server.js` and `public/index.html`.

## Deploy on Render (free)
1. Push this folder to a GitHub repository (`.env` and `data.json` are git-ignored, so your secrets stay out).
2. On https://render.com: New > Blueprint (or New > Web Service), connect the repo. Render reads `render.yaml`.
3. Enter `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`. Leave `BASE_URL` for now (or put your expected address).
4. After the first deploy, copy your service address (e.g. `https://parking-app-xxxx.onrender.com`).
5. In Render > Environment, set `BASE_URL` to that address (no trailing slash). Render redeploys.
6. In Google Cloud > Credentials > your OAuth client, add the redirect URI `<BASE_URL>/auth/google/callback`.
7. OAuth consent screen: keep it in "Testing" and add your friends' Gmail addresses as Test users.

Free-tier caveats: the service sleeps after 15 minutes idle (first load takes about a minute) and its disk is wiped
on restart, so reservations in `data.json` can disappear. Logins survive restarts because sessions are signed cookies.
