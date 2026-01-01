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
    // Get all keys from the database
    const { results } = await env.auth_db.prepare(
        'SELECT key_value, semver_range FROM product_keys'
    ).all();

    let isValid = false;
    if (results) {
        for (const row of results) {
            const key = row.key_value as string;
            const range = row.semver_range as string;

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