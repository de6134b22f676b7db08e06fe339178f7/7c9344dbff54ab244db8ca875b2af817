# Meta app setup (operator)

One shared Meta app serves every site. Console menu names change; items marked **verify** were not checked against current Meta documentation and should be confirmed in the console.

1. Create an app at developers.facebook.com (type: Consumer, or the closest "Authenticate and request data from users with Facebook Login" use case). **verify** the current app-type names.
2. Add the product/use case **Facebook Login for the web**.
3. Facebook Login settings:
   - Client OAuth Login: on. Web OAuth Login: on.
   - **Enforce HTTPS** and **Use Strict Mode for Redirect URIs**: on.
   - **Valid OAuth Redirect URIs**: exactly `BROKER_ORIGIN/v1/facebook/callback` and nothing else.
   - Leave embedded browser OAuth login, login from devices and JavaScript SDK login off.
4. App settings, Basic:
   - **App Domains**: the broker's host (for example `xyz.vercel.app`). **verify**
   - **Privacy Policy URL**: a public page that explains the sign-in data handling (required for Live mode). **verify**
   - Category and app icon as requested by the console.
   - Copy **App ID** and **App Secret** into the broker's `FACEBOOK_APP_ID` and `FACEBOOK_APP_SECRET` (Vercel env, never git).
5. Deauthorize and data deletion (Facebook Login settings, or App settings, Advanced; **verify** location):
   - **Deauthorize Callback URL**: `BROKER_ORIGIN/v1/facebook/deauthorize`
   - **Data Deletion Request URL**: `BROKER_ORIGIN/v1/facebook/data-deletion` (choose "Data Deletion Request Callback URL", not the instructions-URL option)
6. Permissions: `public_profile` only (granted by default, no App Review needed). Do not request email. **verify**
7. Going Live: switch the app from Development to Live mode. Requires Privacy Policy URL, a data deletion mechanism (step 5), an app icon and a category; business verification may be requested depending on use. **verify**. Until Live, only app admins, developers and testers can sign in.
8. Redeploy the broker after setting the env vars, then test `BROKER_ORIGIN/healthz` shows `facebookConfigured: true`.

Graph API version: the broker defaults to the version constant in `src/config.ts` (override with `FACEBOOK_GRAPH_VERSION`). Review it yearly.
