# Campus-Kart-Backend (RebuZZar API)

Express 5 + Mongoose backend for the RebuZZar marketplace. The canonical implementation lives in `src/`.

## Run

```bash
cp .env.example .env     # fill in real values - never commit .env
npm install
npm start                # node src/server.js   (npm run dev = watch mode)
```

The server validates required environment variables at startup and exits with the *names* of anything missing.

## Scripts

| Script | What it does |
|---|---|
| `npm start` / `npm run dev` | start the API (`src/server.js`) |
| `npm test` | unit, HTTP, wire-level (real Mongoose, intercepted driver) and simulated-scenario tests (`node:test`; no database, SMTP or network needed) |
| `npm run check` | syntax-check every backend file |
| `SMOKE_I_USE_A_TEST_DB=yes node scripts/smoke.js` | optional live smoke test against a **test** MongoDB (creates and removes its own documents) |

## Layout

```
src/
  server.js          env -> validate -> connect DB -> listen
  app.js             middleware + routes (importable without a database)
  config/            env, db, cloudinary, passport (Google)
  routes/            URL -> controller wiring, per-route rate limiters / id validation
  controllers/       request handling (auth, product, cart, booking, profile, user, admin)
  services/          booking.service (pricing, availability, transaction), email/ (SMTP + templates)
  middlewares/       auth, admin, upload (magic-byte validated), rateLimiters, sanitize, validateObjectId, errorHandler
  models/            User, Product, Cart, Booking
  utils/             otp, token, serializeUser, escapeHtml, escapeRegex, logger, httpError, constants
```

## API conventions

* Every error response is JSON with a top-level `message` (plus optional flags such as `needsVerification`).
* Bookings: the client sends only `productId` + `quantity`; prices, totals and seller data are taken from the database.
* `GET /api/bookings/:id` and cancellation are owner-only (admins may read); anyone else gets a `404`.
* MongoDB transactions (booking creation) need a replica set (Atlas is one). On a standalone local `mongod` the booking code
  falls back to conditional updates without a transaction and logs a warning.
* Behind a reverse proxy set `TRUST_PROXY=1` so rate limiting sees the real client IP.
