# Express authentication proxy

An express server acting as a proxy to authenticate requests. The proxy will forward all requests to `TARGET` in `.env`
if the user is authenticated. If the user is not authenticated, a redirect to /login is made.

## Get started

To run the server in development mode, nun `npm install && npm run dev`. When the server starts, a database is
created and a default user is added, check `.env` for details about the user.
