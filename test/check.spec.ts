import { env, createExecutionContext, SELF } from 'cloudflare:test';
import { describe, it, expect, beforeEach } from 'vitest';
import { checkHandler } from '../src/handlers/check';

// Helper function to calculate hash for testing
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

describe('checkHandler', () => {
	beforeEach(async () => {
		// Create the table if it doesn't exist
		await env.auth_db.prepare(`
			CREATE TABLE IF NOT EXISTS product_keys (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				key_value TEXT NOT NULL,
				semver_range TEXT NOT NULL,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP
			)
		`).run();

		// Clean up test data
		await env.auth_db.prepare(
			'DELETE FROM product_keys'
		).run();
	});

	describe('Missing parameters', () => {
		it('should return 400 when val is missing', async () => {
			const url = new URL('http://example.com/check?version=1.0.0&salt=test-salt');
			const request = new Request(url.toString());
			const response = await checkHandler(request, env);

			expect(response.status).toBe(400);
			expect(await response.text()).toBe('Missing parameters: val, version, or salt');
		});

		it('should return 400 when version is missing', async () => {
			const url = new URL('http://example.com/check?val=abc123&salt=test-salt');
			const request = new Request(url.toString());
			const response = await checkHandler(request, env);

			expect(response.status).toBe(400);
			expect(await response.text()).toBe('Missing parameters: val, version, or salt');
		});

		it('should return 400 when salt is missing', async () => {
			const url = new URL('http://example.com/check?val=abc123&version=1.0.0');
			const request = new Request(url.toString());
			const response = await checkHandler(request, env);

			expect(response.status).toBe(400);
			expect(await response.text()).toBe('Missing parameters: val, version, or salt');
		});

		it('should return 400 when all parameters are missing', async () => {
			const url = new URL('http://example.com/check');
			const request = new Request(url.toString());
			const response = await checkHandler(request, env);

			expect(response.status).toBe(400);
			expect(await response.text()).toBe('Missing parameters: val, version, or salt');
		});
	});

	describe('Invalid version format', () => {
		it('should return 400 for invalid version format', async () => {
			const url = new URL('http://example.com/check?val=abc123&version=invalid&salt=test-salt');
			const request = new Request(url.toString());
			const response = await checkHandler(request, env);

			expect(response.status).toBe(400);
			expect(await response.text()).toBe('Invalid version format');
		});

		it('should return 400 for version with only major number', async () => {
			const url = new URL('http://example.com/check?val=abc123&version=1&salt=test-salt');
			const request = new Request(url.toString());
			const response = await checkHandler(request, env);

			expect(response.status).toBe(400);
			expect(await response.text()).toBe('Invalid version format');
		});

		it('should return 400 for empty version', async () => {
			const url = new URL('http://example.com/check?val=abc123&version=&salt=test-salt');
			const request = new Request(url.toString());
			const response = await checkHandler(request, env);

			expect(response.status).toBe(400);
			expect(await response.text()).toBe('Missing parameters: val, version, or salt');
		});
	});

	describe('Invalid key rejection', () => {
		it('should return 403 when no keys exist in database', async () => {
			const salt = 'test-salt';
			const val = await calculateHash('nonexistent-key', salt);
			const url = new URL(`http://example.com/check?val=${val}&version=1.0.0&salt=${salt}`);
			const request = new Request(url.toString());
			const response = await checkHandler(request, env);

			expect(response.status).toBe(403);
			expect(await response.text()).toBe('Invalid ID or Version');
		});

		it('should return 403 when hash does not match any key', async () => {
			// Insert a valid key
			await env.auth_db.prepare(
				'INSERT INTO product_keys (key_value, semver_range) VALUES (?, ?)'
			).bind('valid-key', '>=1.0.0').run();

			const salt = 'test-salt';
			const val = await calculateHash('wrong-key', salt);
			const url = new URL(`http://example.com/check?val=${val}&version=1.0.0&salt=${salt}`);
			const request = new Request(url.toString());
			const response = await checkHandler(request, env);

			expect(response.status).toBe(403);
			expect(await response.text()).toBe('Invalid ID or Version');
		});

		it('should return 403 when version does not satisfy semver range', async () => {
			const key = 'valid-key';
			const salt = 'test-salt';
			
			// Insert a key with a specific version range
			await env.auth_db.prepare(
				'INSERT INTO product_keys (key_value, semver_range) VALUES (?, ?)'
			).bind(key, '>=2.0.0').run();

			const val = await calculateHash(key, salt);
			const url = new URL(`http://example.com/check?val=${val}&version=1.0.0&salt=${salt}`);
			const request = new Request(url.toString());
			const response = await checkHandler(request, env);

			expect(response.status).toBe(403);
			expect(await response.text()).toBe('Invalid ID or Version');
		});
	});

	describe('Valid key verification', () => {
		it('should return 200 and server hash for valid key and version', async () => {
			const key = 'valid-key';
			const salt = 'test-salt';
			
			// Insert a valid key
			await env.auth_db.prepare(
				'INSERT INTO product_keys (key_value, semver_range) VALUES (?, ?)'
			).bind(key, '>=1.0.0').run();

			const val = await calculateHash(key, salt);
			const url = new URL(`http://example.com/check?val=${val}&version=1.0.0&salt=${salt}`);
			const request = new Request(url.toString());
			const response = await checkHandler(request, env);

			expect(response.status).toBe(200);
			expect(response.headers.get('Content-Type')).toBe('text/plain');
			
			const serverHash = await response.text();
			const expectedServerHash = await calculateHash(env.SERVER_KEY, salt);
			expect(serverHash).toBe(expectedServerHash);
		});

		it('should return 200 for valid key with exact version match', async () => {
			const key = 'exact-version-key';
			const salt = 'test-salt-exact';
			
			await env.auth_db.prepare(
				'INSERT INTO product_keys (key_value, semver_range) VALUES (?, ?)'
			).bind(key, '1.0.0').run();

			const val = await calculateHash(key, salt);
			const url = new URL(`http://example.com/check?val=${val}&version=1.0.0&salt=${salt}`);
			const request = new Request(url.toString());
			const response = await checkHandler(request, env);

			expect(response.status).toBe(200);
			const serverHash = await response.text();
			const expectedServerHash = await calculateHash(env.SERVER_KEY, salt);
			expect(serverHash).toBe(expectedServerHash);
		});
	});

	describe('Semver range matching', () => {
		it('should accept version within >= range', async () => {
			const key = 'range-key';
			const salt = 'test-salt';
			
			await env.auth_db.prepare(
				'INSERT INTO product_keys (key_value, semver_range) VALUES (?, ?)'
			).bind(key, '>=1.0.0').run();

			const val = await calculateHash(key, salt);
			const url = new URL(`http://example.com/check?val=${val}&version=2.5.3&salt=${salt}`);
			const request = new Request(url.toString());
			const response = await checkHandler(request, env);

			expect(response.status).toBe(200);
		});

		it('should accept version within caret range (^)', async () => {
			const key = 'caret-key';
			const salt = 'test-salt';
			
			await env.auth_db.prepare(
				'INSERT INTO product_keys (key_value, semver_range) VALUES (?, ?)'
			).bind(key, '^1.0.0').run();

			const val = await calculateHash(key, salt);
			const url = new URL(`http://example.com/check?val=${val}&version=1.5.0&salt=${salt}`);
			const request = new Request(url.toString());
			const response = await checkHandler(request, env);

			expect(response.status).toBe(200);
		});

		it('should reject version outside caret range', async () => {
			const key = 'caret-key';
			const salt = 'test-salt';
			
			await env.auth_db.prepare(
				'INSERT INTO product_keys (key_value, semver_range) VALUES (?, ?)'
			).bind(key, '^1.0.0').run();

			const val = await calculateHash(key, salt);
			const url = new URL(`http://example.com/check?val=${val}&version=2.0.0&salt=${salt}`);
			const request = new Request(url.toString());
			const response = await checkHandler(request, env);

			expect(response.status).toBe(403);
		});

		it('should accept version within tilde range (~)', async () => {
			const key = 'tilde-key';
			const salt = 'test-salt';
			
			await env.auth_db.prepare(
				'INSERT INTO product_keys (key_value, semver_range) VALUES (?, ?)'
			).bind(key, '~1.2.0').run();

			const val = await calculateHash(key, salt);
			const url = new URL(`http://example.com/check?val=${val}&version=1.2.5&salt=${salt}`);
			const request = new Request(url.toString());
			const response = await checkHandler(request, env);

			expect(response.status).toBe(200);
		});

		it('should accept version within specific range', async () => {
			const key = 'specific-range-key';
			const salt = 'test-salt';
			
			await env.auth_db.prepare(
				'INSERT INTO product_keys (key_value, semver_range) VALUES (?, ?)'
			).bind(key, '>=1.0.0 <2.0.0').run();

			const val = await calculateHash(key, salt);
			const url = new URL(`http://example.com/check?val=${val}&version=1.9.9&salt=${salt}`);
			const request = new Request(url.toString());
			const response = await checkHandler(request, env);

			expect(response.status).toBe(200);
		});

		it('should reject version outside specific range', async () => {
			const key = 'specific-range-key';
			const salt = 'test-salt';
			
			await env.auth_db.prepare(
				'INSERT INTO product_keys (key_value, semver_range) VALUES (?, ?)'
			).bind(key, '>=1.0.0 <2.0.0').run();

			const val = await calculateHash(key, salt);
			const url = new URL(`http://example.com/check?val=${val}&version=2.0.0&salt=${salt}`);
			const request = new Request(url.toString());
			const response = await checkHandler(request, env);

			expect(response.status).toBe(403);
		});
	});

	describe('Server hash verification', () => {
		it('should return correct server hash based on SERVER_KEY', async () => {
			const key = 'test-key';
			const salt = 'unique-salt-123';
			
			await env.auth_db.prepare(
				'INSERT INTO product_keys (key_value, semver_range) VALUES (?, ?)'
			).bind(key, '*').run();

			const val = await calculateHash(key, salt);
			const url = new URL(`http://example.com/check?val=${val}&version=1.0.0&salt=${salt}`);
			const request = new Request(url.toString());
			const response = await checkHandler(request, env);

			expect(response.status).toBe(200);
			
			const serverHash = await response.text();
			const expectedServerHash = await calculateHash(env.SERVER_KEY, salt);
			
			expect(serverHash).toBe(expectedServerHash);
			expect(serverHash).toHaveLength(64); // SHA-256 produces 64 hex characters
		});

		it('should return different hashes for different salts', async () => {
			const key = 'test-key';
			
			await env.auth_db.prepare(
				'INSERT INTO product_keys (key_value, semver_range) VALUES (?, ?)'
			).bind(key, '*').run();

			const salt1 = 'salt-1';
			const salt2 = 'salt-2';
			
			const val1 = await calculateHash(key, salt1);
			const url1 = new URL(`http://example.com/check?val=${val1}&version=1.0.0&salt=${salt1}`);
			const request1 = new Request(url1.toString());
			const response1 = await checkHandler(request1, env);
			const hash1 = await response1.text();

			const val2 = await calculateHash(key, salt2);
			const url2 = new URL(`http://example.com/check?val=${val2}&version=1.0.0&salt=${salt2}`);
			const request2 = new Request(url2.toString());
			const response2 = await checkHandler(request2, env);
			const hash2 = await response2.text();

			expect(hash1).not.toBe(hash2);
		});
	});

	describe('Multiple keys in database', () => {
		it('should match the correct key when multiple keys exist', async () => {
			const key1 = 'key-1';
			const key2 = 'key-2';
			const key3 = 'key-3';
			const salt = 'test-salt';
			
			// Insert multiple keys
			await env.auth_db.prepare(
				'INSERT INTO product_keys (key_value, semver_range) VALUES (?, ?)'
			).bind(key1, '>=1.0.0').run();
			
			await env.auth_db.prepare(
				'INSERT INTO product_keys (key_value, semver_range) VALUES (?, ?)'
			).bind(key2, '>=2.0.0').run();
			
			await env.auth_db.prepare(
				'INSERT INTO product_keys (key_value, semver_range) VALUES (?, ?)'
			).bind(key3, '>=3.0.0').run();

			// Test with key2
			const val = await calculateHash(key2, salt);
			const url = new URL(`http://example.com/check?val=${val}&version=2.5.0&salt=${salt}`);
			const request = new Request(url.toString());
			const response = await checkHandler(request, env);

			expect(response.status).toBe(200);
		});

		it('should find first matching key when multiple keys satisfy the version', async () => {
			const key1 = 'key-1';
			const key2 = 'key-2';
			const salt = 'test-salt';
			const version = '2.0.0';
			
			// Both keys accept version 2.0.0
			await env.auth_db.prepare(
				'INSERT INTO product_keys (key_value, semver_range) VALUES (?, ?)'
			).bind(key1, '>=1.0.0').run();
			
			await env.auth_db.prepare(
				'INSERT INTO product_keys (key_value, semver_range) VALUES (?, ?)'
			).bind(key2, '>=2.0.0').run();

			// Use key1 which satisfies the version range
			const val = await calculateHash(key1, salt);
			const url = new URL(`http://example.com/check?val=${val}&version=${version}&salt=${salt}`);
			const request = new Request(url.toString());
			const response = await checkHandler(request, env);

			expect(response.status).toBe(200);
		});
	});
});
