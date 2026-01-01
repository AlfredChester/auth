import { env } from 'cloudflare:test';
import { describe, it, expect, beforeEach } from 'vitest';
import { checkHandler } from '../src/handlers/check';
import { calculateHash } from '../src/utils/hash';

describe('checkHandler', () => {
	beforeEach(async () => {
		// Set up test database schema
		await env.auth_db.prepare(`
			CREATE TABLE IF NOT EXISTS product_keys (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				key_value TEXT NOT NULL,
				semver_range TEXT NOT NULL,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP
			)
		`).run();

		// Create indexes
		await env.auth_db.prepare(`
			CREATE INDEX IF NOT EXISTS idx_product_keys_key_value
				ON product_keys(key_value)
		`).run();

		await env.auth_db.prepare(`
			CREATE INDEX IF NOT EXISTS idx_product_keys_semver_range
				ON product_keys(semver_range)
		`).run();

		// Clear any existing data
		await env.auth_db.prepare('DELETE FROM product_keys').run();
		
		// Insert test keys with different semver ranges
		await env.auth_db.prepare(
			'INSERT INTO product_keys (key_value, semver_range) VALUES (?, ?)'
		).bind('test_key_1', '^1.0.0').run();
		
		await env.auth_db.prepare(
			'INSERT INTO product_keys (key_value, semver_range) VALUES (?, ?)'
		).bind('test_key_2', '>=2.0.0 <3.0.0').run();
		
		await env.auth_db.prepare(
			'INSERT INTO product_keys (key_value, semver_range) VALUES (?, ?)'
		).bind('test_key_3', '*').run();
	});

	describe('Missing parameters', () => {
		it('returns 400 when val parameter is missing', async () => {
			const request = new Request('http://example.com/check?version=1.0.0&salt=test_salt');
			const response = await checkHandler(request, env);
			expect(response.status).toBe(400);
			expect(await response.text()).toBe('Missing parameters: val, version, or salt');
		});

		it('returns 400 when version parameter is missing', async () => {
			const request = new Request('http://example.com/check?val=test_val&salt=test_salt');
			const response = await checkHandler(request, env);
			expect(response.status).toBe(400);
			expect(await response.text()).toBe('Missing parameters: val, version, or salt');
		});

		it('returns 400 when salt parameter is missing', async () => {
			const request = new Request('http://example.com/check?val=test_val&version=1.0.0');
			const response = await checkHandler(request, env);
			expect(response.status).toBe(400);
			expect(await response.text()).toBe('Missing parameters: val, version, or salt');
		});

		it('returns 400 when all parameters are missing', async () => {
			const request = new Request('http://example.com/check');
			const response = await checkHandler(request, env);
			expect(response.status).toBe(400);
			expect(await response.text()).toBe('Missing parameters: val, version, or salt');
		});
	});

	describe('Invalid version format', () => {
		it('returns 400 for invalid version format', async () => {
			const request = new Request('http://example.com/check?val=test_val&version=invalid&salt=test_salt');
			const response = await checkHandler(request, env);
			expect(response.status).toBe(400);
			expect(await response.text()).toBe('Invalid version format');
		});

		it('returns 400 for empty version string', async () => {
			const request = new Request('http://example.com/check?val=test_val&version=&salt=test_salt');
			const response = await checkHandler(request, env);
			expect(response.status).toBe(400);
		});

		it('returns 400 for malformed version', async () => {
			const request = new Request('http://example.com/check?val=test_val&version=1.0.x.y&salt=test_salt');
			const response = await checkHandler(request, env);
			expect(response.status).toBe(400);
			expect(await response.text()).toBe('Invalid version format');
		});
	});

	describe('Valid key verification', () => {
		it('returns 200 and server hash for valid key matching semver range', async () => {
			const salt = 'test_salt_123';
			const version = '1.0.0';
			const key = 'test_key_1';
			
			// Calculate the expected hash for the key
			const expectedHash = await calculateHash(key, salt);
			
			// Calculate expected server response
			const expectedServerHash = await calculateHash(env.SERVER_KEY, salt);
			
			const request = new Request(
				`http://example.com/check?val=${expectedHash}&version=${version}&salt=${salt}`
			);
			const response = await checkHandler(request, env);
			
			expect(response.status).toBe(200);
			const responseText = await response.text();
			expect(responseText).toBe(expectedServerHash);
		});

		it('accepts version 1.5.0 with ^1.0.0 range', async () => {
			const salt = 'test_salt_456';
			const version = '1.5.0';
			const key = 'test_key_1';
			
			const expectedHash = await calculateHash(key, salt);
			const expectedServerHash = await calculateHash(env.SERVER_KEY, salt);
			
			const request = new Request(
				`http://example.com/check?val=${expectedHash}&version=${version}&salt=${salt}`
			);
			const response = await checkHandler(request, env);
			
			expect(response.status).toBe(200);
			expect(await response.text()).toBe(expectedServerHash);
		});

		it('accepts version matching wildcard range', async () => {
			const salt = 'test_salt_789';
			const version = '99.99.99';
			const key = 'test_key_3';
			
			const expectedHash = await calculateHash(key, salt);
			const expectedServerHash = await calculateHash(env.SERVER_KEY, salt);
			
			const request = new Request(
				`http://example.com/check?val=${expectedHash}&version=${version}&salt=${salt}`
			);
			const response = await checkHandler(request, env);
			
			expect(response.status).toBe(200);
			expect(await response.text()).toBe(expectedServerHash);
		});
	});

	describe('Invalid key rejection', () => {
		it('returns 403 for incorrect hash', async () => {
			const salt = 'test_salt_123';
			const version = '1.0.0';
			const incorrectHash = 'wrong_hash_value';
			
			const request = new Request(
				`http://example.com/check?val=${incorrectHash}&version=${version}&salt=${salt}`
			);
			const response = await checkHandler(request, env);
			
			expect(response.status).toBe(403);
			expect(await response.text()).toBe('Invalid ID or Version');
		});

		it('returns 403 for non-existent key', async () => {
			const salt = 'test_salt_123';
			const version = '1.0.0';
			const key = 'non_existent_key';
			
			// Calculate hash for a key that doesn't exist in DB
			const hash = await calculateHash(key, salt);
			
			const request = new Request(
				`http://example.com/check?val=${hash}&version=${version}&salt=${salt}`
			);
			const response = await checkHandler(request, env);
			
			expect(response.status).toBe(403);
			expect(await response.text()).toBe('Invalid ID or Version');
		});

		it('returns 403 when using wrong key for correct version', async () => {
			const salt = 'test_salt_123';
			const version = '1.0.0';
			// Using test_key_2 hash but version matches test_key_1 range
			const wrongKeyHash = await calculateHash('test_key_2', salt);
			
			const request = new Request(
				`http://example.com/check?val=${wrongKeyHash}&version=${version}&salt=${salt}`
			);
			const response = await checkHandler(request, env);
			
			expect(response.status).toBe(403);
			expect(await response.text()).toBe('Invalid ID or Version');
		});
	});

	describe('Semver range matching', () => {
		it('rejects version 2.0.0 with ^1.0.0 range', async () => {
			const salt = 'test_salt_semver';
			const version = '2.0.0';  // Outside ^1.0.0 range
			const key = 'test_key_1';
			
			const hash = await calculateHash(key, salt);
			
			const request = new Request(
				`http://example.com/check?val=${hash}&version=${version}&salt=${salt}`
			);
			const response = await checkHandler(request, env);
			
			expect(response.status).toBe(403);
			expect(await response.text()).toBe('Invalid ID or Version');
		});

		it('accepts version 2.5.0 with >=2.0.0 <3.0.0 range', async () => {
			const salt = 'test_salt_range';
			const version = '2.5.0';
			const key = 'test_key_2';
			
			const hash = await calculateHash(key, salt);
			const expectedServerHash = await calculateHash(env.SERVER_KEY, salt);
			
			const request = new Request(
				`http://example.com/check?val=${hash}&version=${version}&salt=${salt}`
			);
			const response = await checkHandler(request, env);
			
			expect(response.status).toBe(200);
			expect(await response.text()).toBe(expectedServerHash);
		});

		it('rejects version 3.0.0 with >=2.0.0 <3.0.0 range', async () => {
			const salt = 'test_salt_boundary';
			const version = '3.0.0';  // Outside range
			const key = 'test_key_2';
			
			const hash = await calculateHash(key, salt);
			
			const request = new Request(
				`http://example.com/check?val=${hash}&version=${version}&salt=${salt}`
			);
			const response = await checkHandler(request, env);
			
			expect(response.status).toBe(403);
			expect(await response.text()).toBe('Invalid ID or Version');
		});

		it('accepts exact version match at lower boundary', async () => {
			const salt = 'test_salt_lower';
			const version = '2.0.0';  // Lower boundary of >=2.0.0 <3.0.0
			const key = 'test_key_2';
			
			const hash = await calculateHash(key, salt);
			const expectedServerHash = await calculateHash(env.SERVER_KEY, salt);
			
			const request = new Request(
				`http://example.com/check?val=${hash}&version=${version}&salt=${salt}`
			);
			const response = await checkHandler(request, env);
			
			expect(response.status).toBe(200);
			expect(await response.text()).toBe(expectedServerHash);
		});
	});

	describe('Server hash verification', () => {
		it('returns correct server hash for integrity checking', async () => {
			const salt = 'unique_salt_for_server_check';
			const version = '1.0.0';
			const key = 'test_key_1';
			
			const clientHash = await calculateHash(key, salt);
			const expectedServerHash = await calculateHash(env.SERVER_KEY, salt);
			
			const request = new Request(
				`http://example.com/check?val=${clientHash}&version=${version}&salt=${salt}`
			);
			const response = await checkHandler(request, env);
			
			expect(response.status).toBe(200);
			const serverHash = await response.text();
			
			// Verify that the server hash is correct
			expect(serverHash).toBe(expectedServerHash);
			expect(serverHash).not.toBe(clientHash);
		});

		it('returns different server hash for different salts', async () => {
			const salt1 = 'salt_one';
			const salt2 = 'salt_two';
			const version = '1.0.0';
			const key = 'test_key_1';
			
			// First request
			const hash1 = await calculateHash(key, salt1);
			const request1 = new Request(
				`http://example.com/check?val=${hash1}&version=${version}&salt=${salt1}`
			);
			const response1 = await checkHandler(request1, env);
			const serverHash1 = await response1.text();
			
			// Second request with different salt
			const hash2 = await calculateHash(key, salt2);
			const request2 = new Request(
				`http://example.com/check?val=${hash2}&version=${version}&salt=${salt2}`
			);
			const response2 = await checkHandler(request2, env);
			const serverHash2 = await response2.text();
			
			// Server hashes should be different for different salts
			expect(serverHash1).not.toBe(serverHash2);
		});

		it('returns content-type text/plain header', async () => {
			const salt = 'test_salt';
			const version = '1.0.0';
			const key = 'test_key_1';
			
			const hash = await calculateHash(key, salt);
			
			const request = new Request(
				`http://example.com/check?val=${hash}&version=${version}&salt=${salt}`
			);
			const response = await checkHandler(request, env);
			
			expect(response.status).toBe(200);
			expect(response.headers.get('Content-Type')).toBe('text/plain');
		});
	});
});
