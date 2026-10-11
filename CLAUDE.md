# CLAUDE.md

Next.js front end of hackerchat, the chat app built for the Applied cryptography course. The README is the stock create-next-app text.

## Commands

```bash
npm run dev     # also: npm run build, npm start, npm run lint
```

## Deployment and domains

Runs on Vercel project `hackerchat-tirp` at https://hackerchat.matejbasic.com since the domain migration of 2026-10-11 (Cloudflare zone `matejbasic.com`, DNS-only record). The old https://hackerchat.vercel.app 301-redirects at the Vercel project level and must stay.

Build-time env (`NEXT_PUBLIC_*` is baked in, so redeploy after changing):

- `NEXT_PUBLIC_WEBSOCKET_CONNECT=wss://chat-ws.matejbasic.com/api/websocket/connect`
- `NEXT_PUBLIC_AUTH_CONNECT=https://hackerchat.matejbasic.com`

The websocket server is the separate repo github.com/matej-basic/hackerchat (Railway), served at chat-ws.matejbasic.com.
