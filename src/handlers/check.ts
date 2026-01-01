import semver from 'semver';

/**
 * Calculate hash using HMAC-SHA256 algorithm
 * @param key The key used for HMAC
 * @param salt The salt to be hashed
 * @returns Hexadecimal string of the hash
 */
async function calculateHash(key: string, salt: string): Promise<string> {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(key);
    const saltData = encoder.encode(salt);

    const cryptoKey = await crypto.subtle.importKey(
        'raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );

    const signature = await crypto.subtle.sign(
        'HMAC', cryptoKey, saltData
    );

    return Array.from(new Uint8Array(signature))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

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

    // 第二阶段：返回 Server Key 加密结果
    // 用于客户端验证服务端身份
    const serverResponse = await calculateHash(env.SERVER_KEY, salt);

    return new Response(serverResponse, {
        status: 200,
        headers: {
            'Content-Type': 'text/plain'
        }
    });
};