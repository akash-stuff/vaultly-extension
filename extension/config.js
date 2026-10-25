// Central place to configure the API base URL used by the extension.
// Point this at your deployed backend in production.
export const API_BASE_URL = 'https://vaultly-service.onrender.com/api';

/**
 * Where the WEB VAULT lives — the React app, not the API. These are different
 * hosts: deriving one from the other by stripping "/api" pointed the "Open web
 * vault" link at the backend, which serves JSON.
 * Change this if the UI is deployed somewhere else.
 */
export const WEB_APP_URL = 'https://vaultly-ui.onrender.com';
