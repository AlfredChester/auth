import semver from 'semver';
import { calculateHash } from '../utils/hash';

export const checkHandler = async (request: Request, env: Env) => {
    const url = new URL(request.url);
    const val = url.searchParams.get('val');
    const version = url.searchParams.get('version');
    const salt = url.searchParams.get('salt');

    if (!val || !version || !salt) {
        return new Response('Missing parameters: val, version, or salt', { status: 400 });
    }

    if (!semver.valid(version)) {
        return new Response('Invalid version format', { status: 400 });
    }

    // Phase one: check ID
    // Note: We fetch all keys because we need to compute HMAC-SHA256 for each key with the
    // client-provided salt, which cannot be done in the database query. The indexes on
    // key_value and semver_range help with query performance. For production systems with
    // a large number of keys, consider implementing caching or partitioning strategies.
    // Keys are ordered by creation date to ensure consistent processing order.
    const { results } = await env.auth_db.prepare(
        'SELECT key_value, semver_range FROM product_keys ORDER BY created_at ASC'
    ).all();

    let isValid = false;
    if (results) {
        for (let i = 0; i < results.length; i++) {
            const row = results[i];
            const key = row.key_value as string;
            const range = row.semver_range as string;

            // Validate the semver range from the database
            if (!semver.validRange(range)) {
                console.warn('Invalid semver range found in database');
                continue;
            }

            // Check if the version satisfies the semver range
            if (semver.satisfies(version, range)) {
                const hash = await calculateHash(key, salt);
                if (hash === val) {
                    isValid = true;
                    break;
                }
            }
        }
    }

    if (!isValid) {
        return new Response('Invalid ID or Version', { status: 403 });
    }

    // Phase two: return SERVER_KEY hash
    // Used for the client to verify server integrity
    const serverResponse = await calculateHash(env.SERVER_KEY, salt);

    return new Response(serverResponse, {
        status: 200,
        headers: {
            'Content-Type': 'text/plain'
        }
    });
};