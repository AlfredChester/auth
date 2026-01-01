# Auth

## Introduction

This project is an out-of-the-box cloud authentication powered by cloudflare workers. You can manage licenses for your software with ease. For multiple products, simply create separate namespaces for each product.

## Usage

1. Clone this repository.
2. Make sure you have `npm` and `wrangler` installed and configured.
3. Run `npm install` to install dependencies
4. Run `wrangler deploy` to publish your project.
5. Run `npx wrangler d1 create auth-db` to create a new D1 database.
6. Update `wrangler.jsonc` with your database ID produced in step 6.
7. Apply migration by running the following command:
   ```bash
   npx wrangler d1 migrate auth-db --local
   # For production:
   npx wrangler d1 migrate auth-db --remote
   ``` 
8.  Your authentication app is now live! 🎉

## License

This project is licensed under the terms of the GNU General Public License v3.0.
