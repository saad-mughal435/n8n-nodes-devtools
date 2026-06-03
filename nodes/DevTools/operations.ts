/**
 * Pure, framework-free implementations of every DevTools operation.
 *
 * This module deliberately imports NOTHING from n8n. Keeping the logic here
 * (and the n8n `execute()` glue in DevTools.node.ts thin) means the whole
 * behaviour can be unit-tested without an n8n execution context — see
 * test/operations.test.ts.
 */
import { createHash, createHmac, randomBytes, randomUUID } from 'node:crypto';
import jwt from 'jsonwebtoken';
import type { Algorithm, JwtPayload } from 'jsonwebtoken';

export type Encoding = 'hex' | 'base64';
export type HashAlgorithm = 'sha256' | 'sha512';

/**
 * n8n's `type: 'json'` parameters arrive either as a raw string (typed by hand)
 * or already parsed (from an expression). Normalise to a value, with a friendly
 * error naming the offending field.
 */
export function parseJsonInput(value: unknown, field: string): any {
	if (typeof value !== 'string') {
		return value;
	}
	try {
		return JSON.parse(value);
	} catch {
		throw new Error(`The "${field}" field does not contain valid JSON.`);
	}
}

/* ------------------------------------------------------------------ JWT */

export interface SignJwtParams {
	payload: Record<string, unknown>;
	secretOrPrivateKey: string;
	algorithm?: Algorithm;
	expiresIn?: string | number;
}

export function signJwt(params: SignJwtParams): string {
	const { payload, secretOrPrivateKey, algorithm = 'HS256', expiresIn } = params;
	if (!secretOrPrivateKey) {
		throw new Error('A signing secret or private key is required.');
	}
	const options: jwt.SignOptions = { algorithm };
	if (expiresIn !== undefined && expiresIn !== '') {
		options.expiresIn = expiresIn as any;
	}
	return jwt.sign(payload, secretOrPrivateKey, options);
}

export interface VerifyJwtParams {
	token: string;
	secretOrPublicKey: string;
	algorithms?: Algorithm[];
}

export interface VerifyJwtResult {
	valid: boolean;
	payload?: JwtPayload | string;
	error?: string;
}

export function verifyJwt(params: VerifyJwtParams): VerifyJwtResult {
	const { token, secretOrPublicKey, algorithms } = params;
	if (!token) {
		throw new Error('A token is required to verify.');
	}
	if (!secretOrPublicKey) {
		throw new Error('A secret or public key is required to verify.');
	}
	try {
		const options: jwt.VerifyOptions = {};
		if (algorithms && algorithms.length > 0) {
			options.algorithms = algorithms;
		}
		const payload = jwt.verify(token, secretOrPublicKey, options);
		return { valid: true, payload };
	} catch (error) {
		// Tampered, expired (exp), or not-yet-valid (nbf) tokens all land here.
		return { valid: false, error: (error as Error).message };
	}
}

/* ----------------------------------------------------------------- Hash */

export function hashString(data: string, algorithm: HashAlgorithm, encoding: Encoding): string {
	return createHash(algorithm).update(data, 'utf8').digest(encoding);
}

export function hmacString(
	data: string,
	key: string,
	algorithm: HashAlgorithm,
	encoding: Encoding,
): string {
	if (!key) {
		throw new Error('An HMAC key is required.');
	}
	return createHmac(algorithm, key).update(data, 'utf8').digest(encoding);
}

/* ------------------------------------------------------------------- ID */

export function uuidV4(): string {
	return randomUUID();
}

// The standard Nano ID alphabet — exactly 64 characters, so masking a random
// byte with `& 63` selects a character with no modulo bias.
const NANOID_ALPHABET = 'useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict';

export function nanoid(size = 21): string {
	if (!Number.isInteger(size) || size <= 0) {
		throw new Error('Nano ID size must be a positive integer.');
	}
	const bytes = randomBytes(size);
	let id = '';
	for (let i = 0; i < size; i++) {
		id += NANOID_ALPHABET[bytes[i] & 63];
	}
	return id;
}

/* --------------------------------------------------------------- base64 */

export function base64Encode(data: string): string {
	return Buffer.from(data, 'utf8').toString('base64');
}

export function base64Decode(data: string): string {
	return Buffer.from(data, 'base64').toString('utf8');
}

/* ------------------------------------------------------------------ CSV */

function uniqueKeys(rows: Array<Record<string, unknown>>): string[] {
	const keys: string[] = [];
	const seen = new Set<string>();
	for (const row of rows) {
		for (const key of Object.keys(row ?? {})) {
			if (!seen.has(key)) {
				seen.add(key);
				keys.push(key);
			}
		}
	}
	return keys;
}

export interface CsvOptions {
	delimiter?: string;
	columns?: string[];
}

export function jsonToCsv(rows: Array<Record<string, unknown>>, options: CsvOptions = {}): string {
	if (!Array.isArray(rows)) {
		throw new Error('JSON to CSV expects an array of objects.');
	}
	const delimiter = options.delimiter || ',';
	const columns = options.columns ?? uniqueKeys(rows);

	const escape = (value: unknown): string => {
		const raw =
			value === null || value === undefined
				? ''
				: typeof value === 'object'
					? JSON.stringify(value)
					: String(value);
		if (
			raw.includes('"') ||
			raw.includes(delimiter) ||
			raw.includes('\n') ||
			raw.includes('\r')
		) {
			return `"${raw.replace(/"/g, '""')}"`;
		}
		return raw;
	};

	const header = columns.map(escape).join(delimiter);
	const body = rows.map((row) => columns.map((col) => escape(row?.[col])).join(delimiter));
	return [header, ...body].join('\r\n');
}

// RFC 4180-style parser: handles quoted fields, escaped ("") quotes, and
// delimiters / newlines inside quotes.
function parseCsv(input: string, delimiter: string): string[][] {
	const rows: string[][] = [];
	let field = '';
	let row: string[] = [];
	let inQuotes = false;
	let i = 0;

	while (i < input.length) {
		const char = input[i];
		if (inQuotes) {
			if (char === '"') {
				if (input[i + 1] === '"') {
					field += '"';
					i += 2;
					continue;
				}
				inQuotes = false;
				i++;
				continue;
			}
			field += char;
			i++;
			continue;
		}
		if (char === '"') {
			inQuotes = true;
			i++;
			continue;
		}
		if (char === delimiter) {
			row.push(field);
			field = '';
			i++;
			continue;
		}
		if (char === '\r') {
			i++;
			continue;
		}
		if (char === '\n') {
			row.push(field);
			rows.push(row);
			field = '';
			row = [];
			i++;
			continue;
		}
		field += char;
		i++;
	}
	row.push(field);
	rows.push(row);
	return rows;
}

export function csvToJson(csv: string, options: CsvOptions = {}): Array<Record<string, string>> {
	const delimiter = options.delimiter || ',';
	const rows = parseCsv(csv, delimiter);
	if (rows.length === 0) {
		return [];
	}
	const header = rows[0];
	const out: Array<Record<string, string>> = [];
	for (let i = 1; i < rows.length; i++) {
		const row = rows[i];
		// Skip a trailing empty line produced by a final newline.
		if (row.length === 1 && row[0] === '') {
			continue;
		}
		const record: Record<string, string> = {};
		header.forEach((key, idx) => {
			record[key] = row[idx] ?? '';
		});
		out.push(record);
	}
	return out;
}

/* --------------------------------------------------------------- Regex */

export interface RegexExtractResult {
	matched: boolean;
	match: string | null;
	index: number | null;
	groups: Record<string, string>;
}

export function regexExtract(text: string, pattern: string, flags = ''): RegexExtractResult {
	if (!pattern) {
		throw new Error('A regular expression pattern is required.');
	}
	let regex: RegExp;
	try {
		regex = new RegExp(pattern, flags);
	} catch (error) {
		throw new Error(`Invalid regular expression: ${(error as Error).message}`);
	}
	const match = regex.exec(text);
	if (!match) {
		return { matched: false, match: null, index: null, groups: {} };
	}
	return {
		matched: true,
		match: match[0],
		index: match.index,
		groups: { ...(match.groups ?? {}) },
	};
}
