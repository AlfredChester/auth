# Auth

## Introduction

This project is an out-of-the-box cloud authentication powered by cloudflare workers. You can manage licenses for your software with ease. For multiple products, simply create separate namespaces for each product.

## Usage

1. Clone this repository.
2. Make sure you have `npm` and `wrangler` installed and configured.
3. Run `npm install` to install dependencies
4. Generate a strong random server key (HMAC secret), for example:
   ```bash
   openssl rand -base64 32
   ```
5. Write the server key to `wrangler.jsonc`.
6. Run `wrangler secret put SERVER_KEY` to store the server key as a secret.
7. Run `npx wrangler d1 create auth-db` to create a new D1 database.
8. Update `wrangler.jsonc` with your database ID produced in step 7.
9. Apply migration by running the following command:
   ```bash
   npx wrangler d1 migrate auth-db --local
   # For production:
   npx wrangler d1 migrate auth-db --remote
   ``` 
10. Your authentication app is now live! 🎉 Use `scripts/add_key.sh` to add your first key. You may also use other scripts to manage keys.

## License

This project is licensed under the terms of the GNU General Public License v3.0.
