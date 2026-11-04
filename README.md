# Roster

A small agent directory: sign in with a username and password, then save each agent's name and responsibility.

## Publish with GitHub Pages

1. In this repository, open **Settings → Pages**.
2. Under **Build and deployment**, set **Source** to **GitHub Actions**.
3. The included workflow publishes the site whenever a change lands on `main`.

The site will appear at `https://raffaelloge.github.io/Agents/` after the workflow finishes.

## Where data is stored

This is a static GitHub Pages site, so the account and roster are stored in the browser's local storage. They are not sent to GitHub or synced to another browser or device. The password is used as a local sign-in gate; this is not server-backed account security. Clearing this browser's site data removes the roster.

