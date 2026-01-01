/**
 * Calculate hash using HMAC-SHA256 algorithm
 * @param key The HMAC secret key
 * @param data The data to be hashed
 * @returns Hexadecimal string of the hash
 */
export async function calculateHash(key: string, data: string): Promise<string> {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(key);
    const dataToHash = encoder.encode(data);

    const cryptoKey = await crypto.subtle.importKey(
        'raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );

    const signature = await crypto.subtle.sign(
        'HMAC', cryptoKey, dataToHash
    );

    return Array.from(new Uint8Array(signature))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}
