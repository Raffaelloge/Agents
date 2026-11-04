# Roster

A small agent directory: sign in with a username and password, then save each agent's name and responsibility. The roster syncs to Supabase so it is available in another browser after signing in.

## Site

Open [https://raffaelloge.github.io/Agents/](https://raffaelloge.github.io/Agents/). GitHub Pages publishes changes pushed to `main`.

## Cloud storage

The public site calls the `agents-api` Supabase Edge Function. Password verification and database access happen in that function. The database stores a salted PBKDF2 password hash; the service key is held only in Supabase. Public tables have row-level security enabled and are not accessible to anonymous browser clients.

The current `raffa` account is provisioned in Supabase. When the account first signs in from the browser that has the old local roster, that roster is copied into cloud storage. Sign in from another browser to load the same roster.

The Supabase function source is in `supabase/functions/agents-api/index.ts`. The schema migration is in `supabase/migrations/20261104020701_agents_cloud_sync.sql`. The deployed backend project is configured separately in Supabase; do not commit service keys or password hashes.
