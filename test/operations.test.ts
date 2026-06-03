import {
	base64Decode,
	base64Encode,
	csvToJson,
	hashString,
	hmacString,
	jsonToCsv,
	nanoid,
	regexExtract,
	signJwt,
	uuidV4,
	verifyJwt,
} from '../nodes/DevTools/operations';

describe('JWT', () => {
	const secret = 'super-secret-value';

	it('signs and verifies a HS256 token round-trip', () => {
		const token = signJwt({ payload: { sub: '42', name: 'Ada' }, secretOrPrivateKey: secret });
		expect(token.split('.')).toHaveLength(3);

		const result = verifyJwt({ token, secretOrPublicKey: secret, algorithms: ['HS256'] });
		expect(result.valid).toBe(true);
		expect((result.payload as { sub: string }).sub).toBe('42');
	});

	it('rejects a token signed with a different secret', () => {
		const token = signJwt({ payload: { sub: '42' }, secretOrPrivateKey: secret });
		const result = verifyJwt({ token, secretOrPublicKey: 'wrong-secret' });
		expect(result.valid).toBe(false);
		expect(result.error).toMatch(/signature/i);
	});

	it('rejects an expired token', () => {
		const past = Math.floor(Date.now() / 1000) - 60;
		const token = signJwt({ payload: { sub: '42', exp: past }, secretOrPrivateKey: secret });
		const result = verifyJwt({ token, secretOrPublicKey: secret });
		expect(result.valid).toBe(false);
		expect(result.error).toMatch(/expired/i);
	});

	it('throws when signing without a secret', () => {
		expect(() => signJwt({ payload: {}, secretOrPrivateKey: '' })).toThrow(/secret/i);
	});
});

describe('Hash / HMAC', () => {
	it('computes a known SHA-256 vector', () => {
		expect(hashString('abc', 'sha256', 'hex')).toBe(
			'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
		);
	});

	it('computes a known HMAC-SHA256 vector', () => {
		const digest = hmacString(
			'The quick brown fox jumps over the lazy dog',
			'key',
			'sha256',
			'hex',
		);
		expect(digest).toBe('f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8');
	});

	it('supports base64 output', () => {
		expect(hashString('abc', 'sha256', 'base64')).toBe(
			'ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=',
		);
	});

	it('throws when an HMAC key is missing', () => {
		expect(() => hmacString('abc', '', 'sha256', 'hex')).toThrow(/key/i);
	});
});

describe('ID generation', () => {
	it('generates a v4 UUID', () => {
		expect(uuidV4()).toMatch(
			/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
		);
	});

	it('generates a Nano ID of the requested size from the safe alphabet', () => {
		const id = nanoid(16);
		expect(id).toHaveLength(16);
		expect(id).toMatch(/^[A-Za-z0-9_-]+$/);
	});

	it('produces distinct Nano IDs', () => {
		expect(nanoid()).not.toBe(nanoid());
	});

	it('rejects a non-positive size', () => {
		expect(() => nanoid(0)).toThrow(/positive/i);
	});
});

describe('base64', () => {
	it('encodes and decodes round-trip', () => {
		expect(base64Encode('hello')).toBe('aGVsbG8=');
		expect(base64Decode('aGVsbG8=')).toBe('hello');
		expect(base64Decode(base64Encode('über — 日本語'))).toBe('über — 日本語');
	});
});

describe('CSV', () => {
	it('serialises objects to CSV, quoting fields that need it', () => {
		const csv = jsonToCsv([
			{ name: 'Ada', note: 'plain' },
			{ name: 'Grace', note: 'has, comma' },
			{ name: 'Quote "Q"', note: 'line\nbreak' },
		]);
		const lines = csv.split('\r\n');
		expect(lines[0]).toBe('name,note');
		expect(lines[1]).toBe('Ada,plain');
		expect(lines[2]).toBe('Grace,"has, comma"');
		expect(lines[3]).toBe('"Quote ""Q""","line\nbreak"');
	});

	it('parses CSV back to objects, honouring quotes and escapes', () => {
		const csv = 'name,note\r\nAda,plain\r\nGrace,"has, comma"\r\n"Quote ""Q""","line\nbreak"';
		const rows = csvToJson(csv);
		expect(rows).toEqual([
			{ name: 'Ada', note: 'plain' },
			{ name: 'Grace', note: 'has, comma' },
			{ name: 'Quote "Q"', note: 'line\nbreak' },
		]);
	});

	it('round-trips JSON -> CSV -> JSON for string values', () => {
		const original = [
			{ id: '1', city: 'Dubai' },
			{ id: '2', city: 'Abu Dhabi' },
		];
		expect(csvToJson(jsonToCsv(original))).toEqual(original);
	});

	it('supports a custom delimiter', () => {
		expect(jsonToCsv([{ a: '1', b: '2' }], { delimiter: ';' })).toBe('a;b\r\n1;2');
	});
});

describe('Regex extract', () => {
	it('returns named capture groups', () => {
		const result = regexExtract('2026-06-03', '(?<year>\\d{4})-(?<month>\\d{2})-(?<day>\\d{2})');
		expect(result.matched).toBe(true);
		expect(result.groups).toEqual({ year: '2026', month: '06', day: '03' });
		expect(result.match).toBe('2026-06-03');
		expect(result.index).toBe(0);
	});

	it('reports a non-match cleanly', () => {
		const result = regexExtract('nothing here', '\\d{4}');
		expect(result.matched).toBe(false);
		expect(result.match).toBeNull();
		expect(result.groups).toEqual({});
	});

	it('throws on an invalid pattern', () => {
		expect(() => regexExtract('x', '(')).toThrow(/invalid regular expression/i);
	});
});
