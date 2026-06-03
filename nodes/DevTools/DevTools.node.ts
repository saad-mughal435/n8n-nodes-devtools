import {
	NodeOperationError,
	type IDataObject,
	type IExecuteFunctions,
	type INodeExecutionData,
	type INodeType,
	type INodeTypeDescription,
} from 'n8n-workflow';
import type { Algorithm } from 'jsonwebtoken';

import {
	base64Decode,
	base64Encode,
	csvToJson,
	hashString,
	hmacString,
	jsonToCsv,
	nanoid,
	parseJsonInput,
	regexExtract,
	signJwt,
	uuidV4,
	verifyJwt,
	type Encoding,
	type HashAlgorithm,
} from './operations';

export class DevTools implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'DevTools',
		name: 'devTools',
		icon: 'file:devtools.svg',
		group: ['transform'],
		version: 1,
		subtitle: '={{ $parameter["operation"] + " (" + $parameter["resource"] + ")" }}',
		description:
			'Developer & crypto utilities: JWT, hashing, IDs, conversions, and regex extraction.',
		defaults: {
			name: 'DevTools',
		},
		inputs: ['main'],
		outputs: ['main'],
		properties: [
			{
				displayName: 'Resource',
				name: 'resource',
				type: 'options',
				noDataExpression: true,
				options: [
					{ name: 'JWT', value: 'jwt' },
					{ name: 'Hash', value: 'hash' },
					{ name: 'ID', value: 'id' },
					{ name: 'Convert', value: 'convert' },
					{ name: 'Extract', value: 'extract' },
				],
				default: 'jwt',
			},

			/* ---------------------------------------------------------- Operations */
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: { show: { resource: ['jwt'] } },
				options: [
					{ name: 'Sign', value: 'sign', action: 'Sign a JWT' },
					{ name: 'Verify', value: 'verify', action: 'Verify a JWT' },
				],
				default: 'sign',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: { show: { resource: ['hash'] } },
				options: [
					{ name: 'Hash', value: 'hash', action: 'Hash a string' },
					{ name: 'HMAC', value: 'hmac', action: 'Compute an HMAC' },
				],
				default: 'hash',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: { show: { resource: ['id'] } },
				options: [
					{ name: 'UUID V4', value: 'uuid', action: 'Generate a UUID v4' },
					{ name: 'Nano ID', value: 'nanoid', action: 'Generate a nano id' },
				],
				default: 'uuid',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: { show: { resource: ['convert'] } },
				options: [
					{ name: 'JSON to CSV', value: 'jsonToCsv', action: 'Convert a JSON array to CSV' },
					{ name: 'CSV to JSON', value: 'csvToJson', action: 'Convert CSV to JSON rows' },
					{ name: 'Base64 Encode', value: 'base64Encode', action: 'Base64 encode text' },
					{ name: 'Base64 Decode', value: 'base64Decode', action: 'Base64 decode text' },
				],
				default: 'jsonToCsv',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: { show: { resource: ['extract'] } },
				options: [{ name: 'Regex', value: 'regex', action: 'Extract with a regular expression' }],
				default: 'regex',
			},

			/* ----------------------------------------------------------- JWT: Sign */
			{
				displayName: 'Payload (JSON)',
				name: 'payload',
				type: 'json',
				default: '{\n  "sub": "1234567890",\n  "name": "Ada Lovelace"\n}',
				displayOptions: { show: { resource: ['jwt'], operation: ['sign'] } },
				description: 'The claims to encode into the token',
			},
			{
				displayName: 'Algorithm',
				name: 'algorithm',
				type: 'options',
				options: [
					{ name: 'HS256', value: 'HS256' },
					{ name: 'HS384', value: 'HS384' },
					{ name: 'HS512', value: 'HS512' },
					{ name: 'RS256', value: 'RS256' },
				],
				default: 'HS256',
				displayOptions: { show: { resource: ['jwt'], operation: ['sign'] } },
				description: 'Signing algorithm. HS* use a shared secret; RS256 uses a PEM private key.',
			},
			{
				displayName: 'Secret or Private Key',
				name: 'jwtSecret',
				type: 'string',
				typeOptions: { password: true },
				default: '',
				displayOptions: { show: { resource: ['jwt'], operation: ['sign'] } },
				description: 'HMAC secret (HS*) or PEM private key (RS256)',
			},
			{
				displayName: 'Expires In',
				name: 'expiresIn',
				type: 'string',
				default: '',
				placeholder: 'e.g. 1h, 7d, 3600',
				displayOptions: { show: { resource: ['jwt'], operation: ['sign'] } },
				description:
					'Optional token lifetime (vercel/ms format such as "1h", or seconds). Leave empty for no expiry.',
			},

			/* --------------------------------------------------------- JWT: Verify */
			{
				displayName: 'Token',
				name: 'token',
				type: 'string',
				typeOptions: { password: true },
				default: '',
				displayOptions: { show: { resource: ['jwt'], operation: ['verify'] } },
				description: 'The JWT to verify',
			},
			{
				displayName: 'Secret or Public Key',
				name: 'jwtSecret',
				type: 'string',
				typeOptions: { password: true },
				default: '',
				displayOptions: { show: { resource: ['jwt'], operation: ['verify'] } },
				description: 'HMAC secret (HS*) or PEM public key (RS256)',
			},
			{
				displayName: 'Allowed Algorithms',
				name: 'algorithms',
				type: 'multiOptions',
				options: [
					{ name: 'HS256', value: 'HS256' },
					{ name: 'HS384', value: 'HS384' },
					{ name: 'HS512', value: 'HS512' },
					{ name: 'RS256', value: 'RS256' },
				],
				default: ['HS256'],
				displayOptions: { show: { resource: ['jwt'], operation: ['verify'] } },
				description:
					'Algorithms accepted during verification. Pinning this prevents algorithm-confusion attacks.',
			},

			/* ------------------------------------------------------- Hash and HMAC */
			{
				displayName: 'Data',
				name: 'data',
				type: 'string',
				typeOptions: { rows: 2 },
				default: '',
				displayOptions: { show: { resource: ['hash'] } },
				description: 'The string to digest',
			},
			{
				displayName: 'Algorithm',
				name: 'hashAlgorithm',
				type: 'options',
				options: [
					{ name: 'SHA-256', value: 'sha256' },
					{ name: 'SHA-512', value: 'sha512' },
				],
				default: 'sha256',
				displayOptions: { show: { resource: ['hash'] } },
				description: 'The digest algorithm',
			},
			{
				displayName: 'Key',
				name: 'hmacKey',
				type: 'string',
				typeOptions: { password: true },
				default: '',
				displayOptions: { show: { resource: ['hash'], operation: ['hmac'] } },
				description: 'The secret key for the HMAC',
			},
			{
				displayName: 'Output Encoding',
				name: 'encoding',
				type: 'options',
				options: [
					{ name: 'Hex', value: 'hex' },
					{ name: 'Base64', value: 'base64' },
				],
				default: 'hex',
				displayOptions: { show: { resource: ['hash'] } },
				description: 'How to encode the digest bytes',
			},

			/* --------------------------------------------------------- ID: Nano ID */
			{
				displayName: 'Size',
				name: 'size',
				type: 'number',
				default: 21,
				typeOptions: { minValue: 1 },
				displayOptions: { show: { resource: ['id'], operation: ['nanoid'] } },
				description: 'Number of characters in the generated Nano ID',
			},

			/* --------------------------------------------------------- Convert */
			{
				displayName: 'Records (JSON Array)',
				name: 'records',
				type: 'json',
				default: '[\n  { "name": "Ada", "role": "admin" }\n]',
				displayOptions: { show: { resource: ['convert'], operation: ['jsonToCsv'] } },
				description: 'An array of objects to flatten into CSV rows',
			},
			{
				displayName: 'CSV Text',
				name: 'csv',
				type: 'string',
				typeOptions: { rows: 4 },
				default: '',
				displayOptions: { show: { resource: ['convert'], operation: ['csvToJson'] } },
				description: 'CSV text whose first row is the header. One output item is emitted per data row.',
			},
			{
				displayName: 'Delimiter',
				name: 'delimiter',
				type: 'string',
				default: ',',
				displayOptions: {
					show: { resource: ['convert'], operation: ['jsonToCsv', 'csvToJson'] },
				},
				description: 'The field delimiter',
			},
			{
				displayName: 'Text',
				name: 'text',
				type: 'string',
				typeOptions: { rows: 2 },
				default: '',
				displayOptions: {
					show: { resource: ['convert'], operation: ['base64Encode', 'base64Decode'] },
				},
				description: 'The text to encode or decode',
			},

			/* ---------------------------------------------------------- Extract */
			{
				displayName: 'Text',
				name: 'text',
				type: 'string',
				typeOptions: { rows: 3 },
				default: '',
				displayOptions: { show: { resource: ['extract'], operation: ['regex'] } },
				description: 'The text to search',
			},
			{
				displayName: 'Pattern',
				name: 'pattern',
				type: 'string',
				default: '',
				placeholder: '(?<year>\\d{4})-(?<month>\\d{2})',
				displayOptions: { show: { resource: ['extract'], operation: ['regex'] } },
				description: 'A regular expression. Use named groups (?&lt;name&gt;…) to label captured fields.',
			},
			{
				displayName: 'Flags',
				name: 'flags',
				type: 'string',
				default: '',
				placeholder: 'gimsu',
				displayOptions: { show: { resource: ['extract'], operation: ['regex'] } },
				description: 'Optional regular-expression flags',
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];

		for (let i = 0; i < items.length; i++) {
			try {
				const resource = this.getNodeParameter('resource', i) as string;
				const operation = this.getNodeParameter('operation', i) as string;

				if (resource === 'jwt' && operation === 'sign') {
					const payload = parseJsonInput(this.getNodeParameter('payload', i), 'Payload (JSON)');
					const secret = this.getNodeParameter('jwtSecret', i) as string;
					const algorithm = this.getNodeParameter('algorithm', i) as Algorithm;
					const expiresIn = this.getNodeParameter('expiresIn', i, '') as string;
					const token = signJwt({
						payload,
						secretOrPrivateKey: secret,
						algorithm,
						expiresIn: expiresIn || undefined,
					});
					returnData.push({ json: { token }, pairedItem: { item: i } });
				} else if (resource === 'jwt' && operation === 'verify') {
					const token = this.getNodeParameter('token', i) as string;
					const secret = this.getNodeParameter('jwtSecret', i) as string;
					const algorithms = this.getNodeParameter('algorithms', i, []) as Algorithm[];
					const result = verifyJwt({ token, secretOrPublicKey: secret, algorithms });
					returnData.push({ json: result as unknown as IDataObject, pairedItem: { item: i } });
				} else if (resource === 'hash') {
					const data = this.getNodeParameter('data', i) as string;
					const algorithm = this.getNodeParameter('hashAlgorithm', i) as HashAlgorithm;
					const encoding = this.getNodeParameter('encoding', i) as Encoding;
					const digest =
						operation === 'hmac'
							? hmacString(data, this.getNodeParameter('hmacKey', i) as string, algorithm, encoding)
							: hashString(data, algorithm, encoding);
					returnData.push({
						json: { algorithm, encoding, digest },
						pairedItem: { item: i },
					});
				} else if (resource === 'id') {
					const value =
						operation === 'nanoid' ? nanoid(this.getNodeParameter('size', i) as number) : uuidV4();
					returnData.push({ json: { id: value }, pairedItem: { item: i } });
				} else if (resource === 'convert' && operation === 'jsonToCsv') {
					const records = parseJsonInput(
						this.getNodeParameter('records', i),
						'Records (JSON Array)',
					) as Array<Record<string, unknown>>;
					const delimiter = this.getNodeParameter('delimiter', i, ',') as string;
					returnData.push({
						json: { csv: jsonToCsv(records, { delimiter }) },
						pairedItem: { item: i },
					});
				} else if (resource === 'convert' && operation === 'csvToJson') {
					const csv = this.getNodeParameter('csv', i) as string;
					const delimiter = this.getNodeParameter('delimiter', i, ',') as string;
					for (const row of csvToJson(csv, { delimiter })) {
						returnData.push({ json: row as IDataObject, pairedItem: { item: i } });
					}
				} else if (resource === 'convert' && operation === 'base64Encode') {
					const text = this.getNodeParameter('text', i) as string;
					returnData.push({ json: { data: base64Encode(text) }, pairedItem: { item: i } });
				} else if (resource === 'convert' && operation === 'base64Decode') {
					const text = this.getNodeParameter('text', i) as string;
					returnData.push({ json: { data: base64Decode(text) }, pairedItem: { item: i } });
				} else if (resource === 'extract' && operation === 'regex') {
					const text = this.getNodeParameter('text', i) as string;
					const pattern = this.getNodeParameter('pattern', i) as string;
					const flags = this.getNodeParameter('flags', i, '') as string;
					returnData.push({
						json: regexExtract(text, pattern, flags) as unknown as IDataObject,
						pairedItem: { item: i },
					});
				} else {
					throw new NodeOperationError(
						this.getNode(),
						`Unsupported operation "${operation}" for resource "${resource}".`,
						{ itemIndex: i },
					);
				}
			} catch (error) {
				if (this.continueOnFail()) {
					returnData.push({
						json: { error: (error as Error).message },
						pairedItem: { item: i },
					});
					continue;
				}
				throw new NodeOperationError(this.getNode(), error as Error, { itemIndex: i });
			}
		}

		return [returnData];
	}
}
