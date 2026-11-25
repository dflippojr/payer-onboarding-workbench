// The bundle check's own tests (#425): replay/test/invariants.mjs against the shared redaction corpus
// (workbench-core/src/test/resources/redaction-corpus.json, which RedactorCorpusTest runs through the Redactor), the
// Redactor's committed outputs (workbench-core/src/test/resources/scanner-grids) and secrets generated at runtime.
// Needs no bundle and no build, so the publish job runs it too:
// node --test replay/test/leaks.test.mjs
// The file keeps its name because .github/workflows/ci.yml and publish-replay-bundle.yml run it by this path.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';
import * as invariants from './invariants.mjs';

const { findJsonLeaks, findTextLeaks } = invariants;
import { build, generateCases, PIECE, placed } from './secret-cases.mjs';

const MASK = '[REDACTED]';
const here = name => fileURLToPath(new URL(name, import.meta.url));
const flagged = text => findTextLeaks(text).length > 0;
const checks = text => findTextLeaks(text).map(leak => leak.check);
const assertFlagged = (text, label = text) => assert.ok(flagged(text), `not flagged: ${label}`);
const assertAccepted = (text, label = text) => assert.deepEqual(findTextLeaks(text), [], `flagged: ${label}`);

// ---------------------------------------------------------------------------------------------------------------------
// The shared corpus (#425 criterion 1): every raw entry is flagged, every harmless one accepted.

const corpus = JSON.parse(readFileSync(here('../../workbench-core/src/test/resources/redaction-corpus.json'), 'utf8'));

for (const e of corpus.text) {
  test(`flags secret: ${e.id} (${e.rule})`, () => assertFlagged(e.input));
}
for (const e of corpus.harmless) {
  test(`ignores harmless text: ${e.id} (${e.rule})`, () => assertAccepted(e.input));
}
for (const e of corpus.headers) {
  test(`flags sensitive header: ${e.name}`, () => {
    assert.equal(findJsonLeaks({ requestHeaders: { [e.name]: [e.value] } }).length, 1);
  });
}
for (const e of corpus.harmlessHeaders) {
  test(`ignores harmless header: ${e.name}`, () => {
    assert.deepEqual(findJsonLeaks({ requestHeaders: { [e.name]: [e.value] } }), []);
  });
}

test('holds every corpus entry it was written against', () => {
  // A corpus that shrinks would pass the loops above with fewer tests.
  assert.deepEqual([corpus.text.length, corpus.harmless.length, corpus.headers.length, corpus.harmlessHeaders.length],
    [99, 36, 10, 2]);
});

// What the Redactor once left behind for a corpus case is a leak to the check, which stays stricter than the Redactor
// so it can catch the next such gap.
const leakedOutputs = {
  'Basic credential before a period': 'Received Authorization: Basic dXNlcjpwYXNz.',
  'credential suffix after the mask': 'Bearer [REDACTED]:SECRETPART',
  'form secret cut at a backslash': 'client_secret=[REDACTED]\\xyzTAIL&x=1',
  'embedded secret cut at an escaped quote': '{"result":"{\\"password\\":\\"[REDACTED]\\"ssTAIL\\"}"}',
  'secret object': '{"private_key":{"kty":"RSA","d":"PRIVATED"}}',
  'secret array': '{"access_token":["ARRSECRET"]}',
  'slash-escaped token read as prose': '{"error_description":"rejected Bearer EchoTok\\/TOKENTAIL+x\\/y=="}',
  'slash-escaped token tail after the mask': '{"error_description":"rejected Bearer [REDACTED]\\/TOKENTAIL"}',
};
for (const [name, text] of Object.entries(leakedOutputs)) {
  test(`flags what Redactor used to leave: ${name}`, () => assertFlagged(text));
}

test('flags a secret object or array in parsed JSON', () => {
  assert.equal(findJsonLeaks({ responseBody: '{"private_key":{"d":"PRIVATED"}}' }).length, 1);
  assert.equal(findJsonLeaks({ details: { accessToken: ['ARRSECRET'] } }).length, 1);
});

// ---------------------------------------------------------------------------------------------------------------------
// Invariant 1: a secret-named member's value is exactly a form the Redactor writes.

const SECRET_NAMES = ['client_secret', 'clientSecret', 'CLIENT-SECRET', 'access_token', 'refresh_token', 'id_token',
  'password', 'api_key', 'apiKey', 'private_key', 'secret', 'client_assertion', 'assertion', 'Authorization',
  'proxy-authorization', 'Cookie', 'Set-Cookie', 'X-Api-Key', 'api-key', 'x-auth-token', 'x-access-token',
  'x-client-secret', '__client__secret__', 'pass-word', 'api\u212Aey'];
const NOT_SECRET_NAMES = ['client_id', 'token_type', 'secretary', 'secrets', 'passwords', 'key', 'token', 'cookies',
  'x-api-keys', 'client secret', 'client.secret', 'authorization_code', 'd', 'k', 'ſecret'];
/** Values no secret name may keep, as JSON. */
const UNMASKED_VALUES = ['"s3cr3t"', '""', '" "', '","', '0', '90000000035', 'true', 'false', '{}', '{"x":"y"}',
  '["s3cr3t"]', '[1]', '[null]', '"[REDACTED] "', '" [REDACTED]"', '"[REDACTED]x"', '"x[REDACTED]"',
  '"[REDACTED][REDACTED]"', '"[redacted]"', '["[REDACTED]","s3cr3t"]', '{"v":"[REDACTED]"}', '"Bearer"',
  '"Bearer  [REDACTED]"', '"Unlisted [REDACTED]"', '"s3cr3t [REDACTED]"'];

test('invariant 1: accepts a secret-named member whose value is the mask or null, at every nesting', () => {
  for (const name of SECRET_NAMES) {
    for (const value of [`"${MASK}"`, 'null']) {
      const member = `${JSON.stringify(name)}:${value}`;
      for (const text of [`{${member}}`, `{"a":1,${member},"b":[2]}`, `{"outer":{"inner":[{${member}}]}}`]) {
        assertAccepted(text);
        assertAccepted(JSON.stringify({ body: text }));
        assertAccepted(JSON.stringify({ body: JSON.stringify({ body: text }) }));
        assertAccepted(`payer said: ${text} and went on`);
      }
    }
  }
});

test('invariant 1: flags a secret-named member with any other value, at every nesting', () => {
  let judged = 0;
  for (const name of SECRET_NAMES) {
    for (const value of UNMASKED_VALUES) {
      // A list of the mask is a bundle file's own header list, judged below; in a recorded text the Redactor writes
      // the mask in its place.
      const member = `${JSON.stringify(name)}:${value}`;
      for (const text of [`{${member}}`, `{"a":1,${member},"b":[2]}`, `{"outer":{"inner":[{${member}}]}}`]) {
        assertFlagged(text);
        assertFlagged(JSON.stringify({ body: text }));
        assertFlagged(JSON.stringify({ body: JSON.stringify({ body: text }) }));
        assertFlagged(`payer said: ${text} and went on`);
        judged += 4;
      }
    }
  }
  assert.equal(judged, SECRET_NAMES.length * UNMASKED_VALUES.length * 12);
});

test('invariant 1: keeps any value of a name that is no secret name', () => {
  for (const name of NOT_SECRET_NAMES) {
    for (const value of ['"plain words"', '0', 'true', '{"x":"y"}', '["a",1]', `"${MASK}"`]) {
      assertAccepted(`{${JSON.stringify(name)}:${value}}`);
    }
  }
});

test('invariant 1: an Authorization-style value may keep a listed scheme in front of the mask, and nothing else', () => {
  for (const name of ['Authorization', 'authorization', 'Proxy-Authorization']) {
    for (const scheme of ['Bearer', 'bearer', 'Basic', 'DPoP', 'Token', 'Digest', 'Negotiate', 'NTLM', 'AWS4-HMAC-SHA256']) {
      assertAccepted(JSON.stringify({ [name]: `${scheme} ${MASK}` }));
      assertAccepted(JSON.stringify({ [name]: [`${scheme} ${MASK}`, `Basic ${MASK}`] }));
      assertFlagged(JSON.stringify({ [name]: `${scheme} ${MASK} tail` }));
      assertFlagged(JSON.stringify({ [name]: `${scheme}\t${MASK}` }));
      assertFlagged(JSON.stringify({ [name]: [`${scheme} ${MASK}`, 's3cr3t'] }));
    }
    assertFlagged(JSON.stringify({ [name]: `s3cr3tword ${MASK}` }));
  }
  // Any other secret name keeps no scheme.
  for (const name of ['Cookie', 'client_secret', 'x-api-key']) {
    assertFlagged(JSON.stringify({ [name]: `Bearer ${MASK}` }));
    assertFlagged(JSON.stringify({ [name]: [`Bearer ${MASK}`] }));
  }
});

test('invariant 1: a list of masked values is a header list in a bundle file, not in a recorded text', () => {
  const headers = { Cookie: [MASK], 'Set-Cookie': [MASK, MASK], Authorization: [`Bearer ${MASK}`], Accept: ['*/*'] };
  assert.deepEqual(findJsonLeaks({ steps: [{ details: { exchanges: [{ requestHeaders: headers }] } }] }), []);
  assert.equal(findJsonLeaks({ requestHeaders: { Cookie: [MASK, 'sid=s3cr3t'] } }).length, 1);
  assert.equal(findJsonLeaks({ requestHeaders: { Cookie: 'sid=s3cr3t' } }).length, 1);
  assert.equal(findJsonLeaks({ requestHeaders: { Authorization: ['s3cr3t'] } }).length, 1);
  // In a recorded text the Redactor writes the mask for such a list, so the list is not its output.
  assertFlagged(JSON.stringify({ Cookie: [MASK] }));
  assert.equal(findJsonLeaks({ responseBody: JSON.stringify({ Cookie: [MASK] }) }).length, 1);
});

test('reads a bundle file as it reads each recorded string in it', () => {
  for (const e of corpus.text) {
    for (const record of [{ responseBody: e.input }, { steps: [{ details: { evidence: [e.input] } }] }, { [e.input]: 1 }]) {
      assert.ok(findJsonLeaks(record).length > 0, `not flagged: ${JSON.stringify(record)}`);
    }
  }
  for (const e of corpus.harmless) {
    assert.deepEqual(findJsonLeaks({ responseBody: e.input, notes: [e.input], nested: { evidence: e.input } }), []);
  }
  assert.deepEqual(findJsonLeaks({ count: 3, ok: true, none: null, list: [1, 'two', { three: 3 }] }), []);
});

// ---------------------------------------------------------------------------------------------------------------------
// Invariant 2: a JWK's private members are the mask.

const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];

test('invariant 2: flags each private member of an object with a kty member, wherever the kty stands', () => {
  for (const member of PRIVATE_MEMBERS) {
    for (const value of ['"s3cr3t"', '""', '7', '["s3cr3t"]', '{"r":"s3cr3t"}', '"[REDACTED]x"']) {
      for (const text of [`{"kty":"RSA","${member}":${value}}`, `{"${member}":${value},"n":"N","kty":"oct"}`,
        `{"keys":[{"kty":"EC","x":"X"},{"kty":"RSA","${member}":${value}}]}`]) {
        assertFlagged(text);
        assertFlagged(JSON.stringify({ body: text }));
        assertFlagged(`evidence: ${text}`);
      }
    }
    for (const value of [`"${MASK}"`, 'null']) {
      assertAccepted(`{"kty":"RSA","${member}":${value},"n":"N","e":"AQAB"}`);
      assertAccepted(JSON.stringify({ body: `{"${member}":${value},"kty":"oct"}` }));
    }
  }
});

test('invariant 2: a private member name outside a JWK is an ordinary name', () => {
  assertAccepted('{"d":"2026-10-29","p":0.05,"q":"query","k":[1,2]}');
  assertAccepted('{"jwk":{"kty":"RSA","n":"N1"},"data":{"d":"2026-11-04","k":[1,2]}}');
  assertAccepted('{"keys":[{"kty":"RSA","n":"N"}],"d":"dimension"}');
});

test('invariant 2: an object a string in which spells kty is judged as a JWK', () => {
  // Such a string may hold the object's own members, written into it; the Redactor masks the private members too.
  assertFlagged('{"note":"kty","d":"s3cr3t"}');
  assertFlagged('{"note":"k\\\\u0074y","d":"s3cr3t"}');
  assertFlagged('{"kty-like":1,"d":"s3cr3t"}');
  assertFlagged('{"keys":[{"kid":"kty-0","n":"N"}],"d":"s3cr3t"}');
  assertAccepted(`{"note":"kty","d":"${MASK}"}`);
});

// ---------------------------------------------------------------------------------------------------------------------
// Invariant 3: what no decoded string may hold.

test('invariant 3: flags a scheme credential and accepts the scheme in front of the mask or of prose', () => {
  const credential = 'FAKE-credential-0001';
  for (const scheme of ['Bearer', 'bearer', 'BEARER', 'Basic', 'Token', 'DPoP', 'dpop']) {
    for (const separator of [' ', '\t', '  ']) {
      for (const [before, after] of [['', ''], ['rejected ', ' again'], ['(', ')'], ['"', '"'], ['x=', '&y=1'], ['', ', next']]) {
        const text = `${before}${scheme}${separator}${credential}${after}`;
        assert.ok(checks(text).includes('scheme credential'), text);
        assert.ok(flagged(JSON.stringify({ error_description: text })), text);
        assertAccepted(`${before}${scheme} ${MASK}${after}`);
      }
    }
  }
  for (const separator of ['\n', '\r\n', '\f', '\u000B', '%20', '+']) {
    assertFlagged(`Bearer${separator}${credential}`);
  }
  for (const separator of ['\n', '\r\n', '\f', '\u000B']) assertFlagged(`Basic${separator}RkFLRTpOT1RSRUFM`);
  // After Token and DPoP only a space or a tab separates: a word on the next line is not their credential.
  assertAccepted(`issue a token\n${credential}`);
  assertAccepted('q=missing+bearer+token');
  for (const prose of ['missing bearer token', 'Basic authentication is required', 'Token expired.', 'DPoP proof required',
    'Bearer realm="payer", error="invalid_token"', 'token endpoint: https://payer.example/token', 'POST /oauth/token -> 200']) {
    assertAccepted(prose);
  }
  // The base64 of a user:pass pair is a credential even when it is all letters.
  assertFlagged('Authorization: Basic dXNlcjpwYXNz');
  assertFlagged('Basic dXNlcjpwYXNz.');
});

test('invariant 3: flags the rest of a credential behind a mask', () => {
  for (const tail of [':SECRETPART', '/TAIL', '.TAIL', '%2FTAIL', '=', 'TAIL', '0', '_x', '-x']) {
    assertFlagged(`Bearer ${MASK}${tail}`);
    assertFlagged(JSON.stringify({ note: `rejected Basic ${MASK}${tail}` }));
    assertFlagged(`client_secret=${MASK}${tail}`);
    assertFlagged(`Cookie: ${MASK}${tail}`);
    assertFlagged(`{"password":"${MASK}${tail}"}`);
    assertFlagged(`cut {"a":1,"password":"${MASK}"${tail}`);
  }
  assertFlagged(`Bearer\n${MASK}TAIL`);
  for (const text of [`Bearer ${MASK}`, `Bearer ${MASK}, Basic ${MASK}`, `(Bearer ${MASK})`, `"Bearer ${MASK}"`, `a ${MASK}.`,
    `${MASK} tail`, `client_secret=${MASK}&x=1`]) assertAccepted(text);
  // The mask the Redactor writes to the end of a text it stops reading may stand right behind a value's own mask.
  for (const text of [`then Bearer ${MASK}${MASK}`, `api_key=${MASK}${MASK}`, `Cookie: ${MASK}${MASK}`, `he said "password":"${MASK}"${MASK}`,
    `${MASK}${MASK}`]) assertAccepted(text);
});

test('invariant 3: flags key armor of any label, whole or cut', () => {
  for (const label of ['PRIVATE KEY', 'RSA PRIVATE KEY', 'EC PRIVATE KEY', 'OPENSSH PRIVATE KEY', 'PGP PRIVATE KEY BLOCK',
    'CERTIFICATE', 'PUBLIC KEY', '']) {
    const header = `-----BEGIN ${label}-----`;
    for (const text of [`${header}\nFAKEKEYBODY\n-----END ${label}-----`, `pasted:\n${header}\nFAKEKEYBODY`, header,
      `${header}${MASK}`]) {
      assert.ok(checks(text).includes('key armor'), text);
      assertFlagged(JSON.stringify({ note: text }));
      assertFlagged(JSON.stringify({ body: JSON.stringify({ note: text }) }));
    }
  }
  assertAccepted('paste the PGP PRIVATE KEY BLOCK into the vault, not here');
  assertAccepted(`key:\n${MASK}\ndone`);
});

const b64 = text => Buffer.from(text, 'utf8').toString('base64url');
const jwt = (header, payload, signature) => `${b64(JSON.stringify(header))}.${b64(JSON.stringify(payload))}.${signature}`;

test('invariant 3: flags a JWT signature and accepts the token with its signature masked', () => {
  const token = jwt({ alg: 'none' }, { sub: 'fake' }, 'FAKESIGNATURE0001NOTREAL');
  const masked = jwt({ alg: 'none' }, { sub: 'fake' }, MASK);
  for (const [before, after] of [['', ''], ['client_assertion is ', ''], ['token:\n', '\nend'], ['"', '"'], ['(', ')'], ['x=', '&y=1']]) {
    assert.ok(checks(`${before}${token}${after}`).includes('JWT signature'), `${before}${token}${after}`);
    assertFlagged(JSON.stringify({ debug: `${before}${token}${after}` }));
    assertAccepted(`${before}${masked}${after}`);
    assertAccepted(JSON.stringify({ debug: `${before}${masked}${after}` }));
  }
  // No signature: a token cut after its payload, or an unsigned one.
  assertAccepted(token.slice(0, token.lastIndexOf('.')));
  assertAccepted(token.slice(0, token.lastIndexOf('.') + 1));
  // A second token in the same run of token characters, and one after a dash.
  assertFlagged(`${masked.slice(0, -MASK.length)}.${token}`);
  assertFlagged(`id-${token}`);
});

test('invariant 3: flags a JWT whose header or payload holds a secret once decoded', () => {
  const secretClaims = [{ client_secret: 's3cr3t' }, { ctx: { password: 's3cr3t' } }, { jwk: { kty: 'RSA', d: 's3cr3t' } },
    { note: 'Bearer FAKE-credential-0002' }, { pem: '-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----' },
    { body: JSON.stringify({ access_token: 's3cr3t' }) }, { access_token: ',' }, { api_key: '' }, { secret: [] },
    { inner: jwt({ alg: 'none' }, { sub: 'x' }, 'FAKESIGNATURE0002') }];
  for (const claim of secretClaims) {
    for (const token of [jwt({ alg: 'none' }, { iss: 'p', ...claim }, MASK), jwt({ alg: 'none', ...claim }, { sub: 'x' }, MASK),
      jwt({ alg: 'none' }, { iss: 'p', ...claim }, '')]) {
      assert.ok(checks(token).includes('JWT that holds a secret'), JSON.stringify(claim));
      assertFlagged(JSON.stringify({ note: `sent ${token}` }));
    }
  }
  for (const claim of [{ sub: 'user-1' }, { client_secret: MASK }, { jwk: { kty: 'RSA', n: 'N', d: MASK } }, { scope: 'system/*.read' }]) {
    assertAccepted(jwt({ alg: 'none' }, { iss: 'p', ...claim }, MASK));
  }
});

test('invariant 3: flags a form or query secret and accepts it masked', () => {
  for (const key of ['client_secret', 'Client_Secret', 'clientSecret', 'client-secret', 'access_token', 'ACCESS_TOKEN',
    'refresh_token', 'id_token', 'password', 'api_key', 'apikey', 'private_key', 'secret', 'assertion', '_password_']) {
    for (const [before, after] of [['', ''], ['grant_type=client_credentials&', '&scope=x'], ['GET /token?', ' HTTP/1.1'],
      ['sent:\n', '\nend'], ['"', '"']]) {
      for (const value of ['FAKE-form-secret-0001', '', 'x', 'FAKE\\x-0002', `${MASK}x`]) {
        const text = `${before}${key}=${value}${after}`;
        assert.ok(checks(text).includes('form secret'), text);
        assertFlagged(JSON.stringify({ debug: text }));
      }
      assertAccepted(`${before}${key}=${MASK}${after}`);
    }
  }
  for (const text of ['grant_type=client_credentials&scope=system%2F*.read', 'xclient_secret=1', 'my_password=1', 'secretary=jo']) {
    assertAccepted(text);
  }
});

test('invariant 3: flags a credential header line and accepts it masked, blank or as prose', () => {
  for (const name of ['Authorization', 'authorization', 'Proxy-Authorization', 'Cookie', 'Set-Cookie', 'X-Api-Key', 'api-key',
    'apikey', 'x-auth-token', 'x-access-token', 'x-client-secret', 'COOKIE']) {
    for (const [before, after] of [['', ''], ['HTTP/1.1 401 Unauthorized\n', '\nContent-Length: 0'], ['a\r\n', '\r\nb'], ['  ', ''],
      ['x\u2028', '']]) {
      const line = `${before}${name}: sid=FAKE-header-line-0001; theme=dark${after}`;
      assert.ok(checks(line).includes('credential header line'), line);
      assertFlagged(JSON.stringify({ debug: line }));
      assertAccepted(`${before}${name}: ${MASK}${after}`);
      assertAccepted(`${before}${name}:${after}`);
      // Anything after the mask on the line is part of the value.
      assertFlagged(`${before}${name}: ${MASK} x${after}`);
      assertFlagged(`${before}${name}: ${MASK} ${after}`);
    }
  }
  assertAccepted(`Authorization: Bearer ${MASK}`);
  assertAccepted('Authorization: Bearer access token required');
  assertFlagged(`Cookie: Bearer ${MASK}`);
  assertFlagged('Proxy-Authorization: FAKEproxycred0056 sent twice');
  assertFlagged('Authorization: Token abcdef');
  assertAccepted('see the Cookie: header docs; send the X-Api-Key: header too');
});

test('invariant 3: flags a quoted secret name in text whose value is not a written form at a strict value end', () => {
  for (const name of ['client_secret', 'password', 'Cookie', 'access\\u005ftoken']) {
    for (const value of ['"s3cr3t"', '"s3cr3t', 's3cr3t', '7', 'true', '{"x":1', '["s3cr3t"', `"${MASK}"x`, `"${MASK}`,
      `"${MASK}""`, `"${MASK}\\"`, 'nullx', `"${MASK}":`]) {
      for (const [before, after] of [['', ''], ['cut {"a":1,', ''], ['x ', ' y'], ['', '\nnote']]) {
        const text = `${before}"${name}":${value}${after}`;
        if (after === ' y' && (value === `"${MASK}"x` || value === 'nullx')) continue;
        assertFlagged(text);
      }
    }
    for (const value of [`"${MASK}"`, 'null']) {
      for (const after of ['', ',', '}', ']', ' ', '\n', '\t', ',"b":2}']) {
        assertAccepted(`"${name}":${value}${after}`);
        assertAccepted(`"${name}" : ${value}${after}`);
      }
    }
  }
  assertAccepted(`"Authorization":"Bearer ${MASK}"`);
  assertFlagged(`"Authorization":"Bearer ${MASK}" x`.replace(' x', 'x'));
  // A list after a secret name in text is a JSON value of its own there, which the Redactor masks whole.
  assertFlagged(`"Authorization":["Bearer ${MASK}","Basic ${MASK}"]`);
  assertFlagged(`"Authorization":["Bearer ${MASK}","s3cr3t"]`);
  assertFlagged(`"Cookie":["${MASK}"]`);
  // With a kty name in the text, a JWK's private member names are secret names too.
  assertFlagged('cut {"kty":"RSA","d":"s3cr3t"');
  assertAccepted(`cut {"kty":"RSA","d":"${MASK}"`);
  assertAccepted('cut {"alg":"RS256","d":"2026-11-24"');
  assertAccepted('the client_secret is required and the password must be set');
});

// ---------------------------------------------------------------------------------------------------------------------
// Invariant 4: secret vocabulary next to a spelling the Redactor does not write.

test('invariant 4: reads a quote or backslash spelled as an escape as a plain one, in a decoding', () => {
  const B = '\\';
  // The same field at each spelling of its quotes: every spelling is read by the rule for the plain one.
  const quotes = ['"', `${B}"`, `${B}u0022`, `${B}${B}${B}"`, `${B}${B}u0022`, `${B}u005c"`, `${B}u005cu0022`, `${B}${B}${B}u0022`,
    `${B}u005c${B}u005cu0022`, `${B}${B}${B}${B}${B}${B}${B}"`];
  let judged = 0;
  for (const q of quotes) {
    for (const name of ['password', 'client_secret', 'Cookie']) {
      for (const [before, after] of [['', ''], ['he said "\n', ''], ['{', '}'], ['x {"a":1,', ''], ['', ', more']]) {
        assertFlagged(`${before}${q}${name}${q}:${q}s3cr3t${q}${after}`);
        assertFlagged(JSON.stringify({ body: `${before}${q}${name}${q}:${q}s3cr3t${q}${after}` }));
        judged += 2;
      }
      // What the Redactor leaves for it: the value masked, in the same quotes.
      assertAccepted(`he said "\n${q}${name}${q}:${q}${MASK}${q}`);
    }
  }
  assert.equal(judged, quotes.length * 3 * 5 * 2);
});

test('invariant 4: flags a masked value whose closing quote is spelled at another level than its opening one', () => {
  const B = '\\';
  assertAccepted(`he said "\n${B}"password${B}u0022${B}u000C:\t${B}u0022${MASK}${B}u0022`);
  assertFlagged(`he said "\n${B}${B}${B}"password${B}u0022${B}u000C:\t${B}u0022${MASK}${B}${B}u0022`);
  assertFlagged(`${B}"password${B}u0022${B}u000C:\t${B}u0022${MASK}`);
  assertFlagged(`"x":"${B}"password${B}u0022${B}u000C:\t${B}u0022${MASK}${B}${B}${B}${B}"`);
});

test('invariant 4: a text the Redactor leaves on its own is flagged where a JSON string holds it', () => {
  const B = '\\';
  const field = `x ${B}u0022password${B}u0022\u000b:${B}u0022${MASK}${B}"`;
  // On its own the text is what the Redactor leaves; inside JSON its closing quote meets the string's.
  assertAccepted(field);
  assertFlagged(JSON.stringify({ body: field, y: 1 }));
  // A bundle file holds each recorded text as the Redactor left it (decision 8 on #425): accepted there as on its own.
  assert.deepEqual(findJsonLeaks({ responseBody: field }), []);
  assert.deepEqual(invariants.findFileLeaks(JSON.stringify({ body: field, y: 1 })), []);
  // A recorded text that holds it in a JSON string is one the Redactor masks, in a file as well.
  assert.ok(findJsonLeaks({ responseBody: JSON.stringify({ body: field }) }).length > 0);
});

test('invariant 4: flags a JSON-looking start that does not parse before secret vocabulary', () => {
  const B = '\\';
  const check = 'JSON-looking start that does not parse, before secret vocabulary';
  for (const start of ['{"a":1,', '{"a":"b', `{${B}"a${B}":1,`, '[{"a":1},', '{ "a" 1,', "{'a':1,"]) {
    for (const vocabulary of ['client_secret: s3cr3t', 'password=hunter2', `"kty":"RSA","d${B}":"x"`, '-----BEGIN',
      `${B}u0022api_key${B}u0022: ${B}u0022s3cr3t`, 'Set-Cookie = sid']) {
      assert.ok(checks(`${start} ${vocabulary}`).includes(check), `${start} ${vocabulary}`);
      assert.ok(checks(`log line ${start} tail and then ${vocabulary}`).includes(check), `${start} ${vocabulary}`);
    }
    // No vocabulary, or a name in prose that is no key: the broken start hides nothing.
    for (const prose of ['plain words', 'access_token present', 'the password must be set', 'kty and d']) {
      assertAccepted(`${start} ${prose}`);
    }
  }
  // Redacted text read again (an excerpt of a redacted body cut by the size limit): a key whose value already is the
  // mask is no vocabulary as spelled.
  assertAccepted(`{"client_secret":"${MASK}","n":`);
  assertAccepted(`{"a":{"password":"${MASK}"},"list":[1,`);
  // A start that reads hides nothing, and neither does a bracket that starts no JSON.
  assertAccepted('[INFO] client_secret: see the docs');
  assertAccepted('{code} password: see the docs');
  assertAccepted('ok {"a":1} password: see the docs');
});

test('invariant 4: flags JSON whose member names repeat, which JSON.parse reads by its last one only', () => {
  assertFlagged(`{"client_secret":"s3cr3t","client_secret":"${MASK}"}`);
  assertFlagged(`{"a":{"password":"s3cr3t","password":null}}`);
  assertFlagged(`{"kty":"RSA","d":"s3cr3t","d":"${MASK}"}`);
  assertFlagged(JSON.stringify({ body: `{"client_secret":"s3cr3t","client_secret":"${MASK}"}` }));
  assertFlagged(`evidence: {"client_secret":"s3cr3t","client_secret":"${MASK}"}`);
  assertFlagged(`{"cl\\u0069ent_secret":"s3cr3t","client_secret":"${MASK}"}`);
  // The Redactor masks such JSON whole, so even a harmless repeat is not its output.
  assert.deepEqual(checks('{"a":1,"a":2}'), ['JSON that repeats a member name']);
  // The same name in two objects repeats nothing; embedded in text with no vocabulary a repeat is kept as it came.
  assertAccepted('{"a":{"x":1},"b":{"x":2},"c":[{"x":3},{"x":4}]}');
  assertAccepted('log: {"a":1,"a":2}');
});

test('invariant 4: reads a member name as a decoding of the written JSON reads it', () => {
  const B = '\\';
  // Written out, the name sits between quotes: backslashes at its end escape the closing one, a quote at its start
  // closes the opening one, and a quote and a colon inside it end one member and start the next.
  for (const name of [`client_secret${B}`, `client_secret${B}${B}`, `Cookie${B}${B}${B}`, '"client_secret', 'password":"x', `password${B}":${B}"x`,
    'a":1,"api_key']) {
    assertFlagged(JSON.stringify({ [name]: 's3cr3t' }));
    assertFlagged(JSON.stringify({ body: JSON.stringify({ [name]: 's3cr3t' }) }));
    assertFlagged(`evidence: ${JSON.stringify({ [name]: 's3cr3t' })}`);
    assert.ok(findJsonLeaks({ responseBody: JSON.stringify({ [name]: 's3cr3t' }) }).length > 0);
  }
  // A name no decoding reads as a secret name is an ordinary one.
  for (const name of [`${B}client_secret`, `client_secret${B}"`, `cli${B}ent_secret`, '"password"', `password${B}u0022`, 'password:',
    ' password', `password${B}n`, `client${B}id`]) {
    assertAccepted(JSON.stringify({ [name]: 'plain' }));
  }
  // The same for a JWK's private members, read in the object the decoding shows.
  for (const name of [`d${B}`, `d${B}${B}`, 'x":1,"d', `k${B}`]) {
    assertFlagged(JSON.stringify({ kty: 'RSA', [name]: 's3cr3t' }));
    assertFlagged(JSON.stringify({ keys: [{ n: 'N', [name]: 's3cr3t', kty: 'oct' }] }));
    assertAccepted(JSON.stringify({ [name]: 'plain' }));
    assertAccepted(JSON.stringify({ a: { kty: 'RSA' }, [name]: 'plain' }));
    assertAccepted(JSON.stringify({ kty: 'RSA', data: { [name]: 'plain' } }));
  }
  assertAccepted(JSON.stringify({ kty: 'RSA', '"d': 'plain' }));
});

test('invariant 4: a masked value in a string must end before the string does', () => {
  const B = '\\';
  // Written out, the string's closing quote follows its content; a decoding puts it right behind the value's own.
  assertFlagged(`{"note":"x${B}"password${B}":${B}"${MASK}${B}""}`);
  assertFlagged(`{"note":"x${B}"password${B}":${B}"${MASK}"}`);
  assertFlagged(`{"note":"password${B}":null"}`);
  assertFlagged(`{"a":["x${B}"password${B}":${B}"${MASK}"]}`);
  assertAccepted(`{"note":"x${B}"password${B}":${B}"${MASK}${B}" "}`);
  assertAccepted(`{"note":"a${B}"","password":"${MASK}"}`);
  assertAccepted(`x${B}"password${B}":${B}"${MASK}${B}"`);
});

test('invariant 3: reads a scheme\'s separator and credential as JSON escapes in place, as spelled', () => {
  const B = '\\';
  // Text that is not JSON keeps its escapes: a credential a serializer escaped is one whatever it decodes to.
  for (const text of [`Basic${B}np${B}u0064lan`, `rejected Bearer FakeTok${B}/tail-0001`, `Bearer${B}tFAKE-credential-0005`,
    `Bearer${B}u0020Fake${B}u002Bcredential`, `x${B}nBearer FAKE-credential-0006`, `[{"m":"Basic${B}np${B}u0064lan"}`]) {
    assertFlagged(text);
  }
  // In JSON the same escapes are the string's own spelling, and the decoded string is prose.
  assertAccepted(`{"m":"Basic${B}np${B}u0064lan"}`);
  assertAccepted(`{"m":"Missing bearer${B}ntoken"}`);
});

test('invariant 3: a header line that ends a text that is one JSON string ends at its closing quote', () => {
  const B = '\\';
  // No object or array bounds such a string, so the Redactor reads the line through the quote and masks the text.
  for (const text of [`"he said ${B}"u0022${B}r${B}nCookie: ${MASK}"`, `"Cookie: ${MASK}${B}nSet-Cookie: ${MASK}"`,
    `{"body":"${B}"he said ${B}${B}${B}"${B}${B}nCookie: ${MASK}${B}""}`]) {
    assertFlagged(text);
  }
  for (const text of [`"Cookie: ${MASK}"`, `"Authorization: Bearer ${MASK}"`, `{"debug":"echoed:${B}nCookie: ${MASK}"}`,
    `{"debug":"echoed:${B}nCookie: ${MASK}${B}nend"}`, `"he said ${B}nCookie: ${MASK}${B}n"`,
    JSON.stringify(JSON.stringify({ body: `"x" "\nCookie: ${MASK}` }))]) {
    assertAccepted(text);
  }
});

test('invariant 4: reads a JWK that only a decoding shows, also one that is not JSON there', () => {
  const B = '\\';
  // A member name that a decoding reads as more than one member: which part a private value belongs to is unknown.
  assertFlagged(`{"kty":"RSA","x${B}":1,${B}"y":"plain"}`);
  assertFlagged(`{"note":"kty","x${B}":1,${B}"y":"plain"}`);
  assertAccepted(`{"alg":"RS256","x${B}":1,${B}"y":"plain"}`);
  // A JWK two decodings down whose private member has a value, between the same braces as its kty member.
  const broken = `{"body":"{${B}"dp${B}${B}u0022:${B}t{${B}"x${B}":${B}"FAKE-jwk-0001${B}+"} ,${B}"kty${B}":${B}"o${B}"oct${B}"}`;
  assertFlagged(`${broken}"}`);
  assertFlagged(`evidence: ${broken}"} and more`);
  // Not a member there, or not between a JWK's braces.
  assertAccepted(`{"kty":"RSA","${B}"d":"plain"}`);
  // Decision 6: a key-type name and colon anywhere in such a decoding counts, also where no member starts.
  assertFlagged(`{"body":"kty${B}":${B}"oct${B}",${B}"d${B}":${B}"plain${B}"}"}`);
  assertAccepted(`{"body":"kty${B}":${B}"oct${B}",${B}"d${B}":${B}"${MASK}${B}"}"}`);
  // A string that is JSON as a whole is read as JSON: a private name outside the JWK's object is any name.
  assertAccepted(`{"body":"{${B}"jwk${B}":{${B}"kty${B}":${B}"RSA${B}"},${B}"data${B}":{${B}"d${B}":${B}"2026-11-04${B}"}}"}`);
});

test('invariant 4: flags JSON nested deeper than the Redactor reads, and escapes deeper than the check decodes', () => {
  const deep = depth => `${'['.repeat(depth)}"x"${']'.repeat(depth)}`;
  assertAccepted(deep(128));
  assert.deepEqual(checks(deep(129)), ['JSON nested deeper than the Redactor reads']);
  assertFlagged(`${'{"a":'.repeat(200)}{"client_secret":"s3cr3t"}${'}'.repeat(200)}`);
  assertFlagged(deep(200_000));
  assertAccepted(`log ${deep(129)}`);
  assertFlagged(`log ${deep(129)} client_secret: s3cr3t`);
  // A chain of escaped backslashes that still decodes after the bound.
  assertAccepted(`path ${'\\u005c'.repeat(8)}n`);
  assert.ok(checks(`note \\${'u005c'.repeat(40)}u0022`).includes('escapes deeper than the check decodes'));
  assertAccepted(`note \\${'u005c'.repeat(20)}n`);
});

test('reads JSON held in JSON strings level by level, and as text past the level bound', () => {
  const nest = (text, levels) => {
    let out = text;
    for (let i = 0; i < levels; i++) out = JSON.stringify({ body: out });
    return out;
  };
  for (const levels of [0, 1, 2, 3, 5, 8, 9, 12, 16]) {
    assertFlagged(nest('{"client_secret":"s3cr3t"}', levels), `${levels} levels`);
    assertFlagged(nest('{"kty":"oct","k":"s3cr3t"}', levels), `${levels} levels`);
    assertFlagged(nest('rejected Bearer FAKE-credential-0003', levels), `${levels} levels`);
    assertFlagged(nest('client_secret=FAKE-form-secret-0003', levels), `${levels} levels`);
    assertAccepted(nest('{"token_type":"Bearer","note":"plain words"}', levels), `${levels} levels`);
  }
  for (const levels of [0, 1, 2, 3, 5, 8]) {
    assertAccepted(nest(`{"client_secret":"${MASK}","token_type":"Bearer"}`, levels), `${levels} levels`);
    assertAccepted(nest(`{"kty":"oct","k":"${MASK}"}`, levels), `${levels} levels`);
  }
  // Past the bound the string is text, where a JSON-looking start with a secret name after it is flagged even when
  // the value is masked: the Redactor masks such a string from that start.
  for (const levels of [9, 12, 16]) {
    assertFlagged(nest(`{"client_secret":"${MASK}","token_type":"Bearer"}`, levels), `${levels} levels`);
  }
});

test('judges each JSON value embedded in text, and the text around it', () => {
  assertFlagged('payer said: {"client_secret":"s3cr3t"} then stopped');
  assertFlagged('a {"ok":1} b {"kty":"RSA","d":"s3cr3t"} c');
  assertFlagged('a {"ok":1} b [{"body":"{\\"password\\":\\"s3cr3t\\"}"}] c');
  assertFlagged('a {"ok":1} then Bearer FAKE-credential-0004');
  assertFlagged('"client_secret": {"ok":1}');
  assertFlagged('client_secret={"ok":1}');
  assertAccepted(`payer said: {"client_secret":"${MASK}"} then Bearer ${MASK}`);
  assertAccepted(`a {"ok":1} b [{"body":"{\\"password\\":\\"${MASK}\\"}"}] c`);
});

test('automated review r1: a bundle file that repeats a member name is flagged, whatever JSON.parse keeps of it', () => {
  const file = `{"steps":[{"details":{"password":"s3cr3t","password":"${MASK}"}}]}`;
  assert.deepEqual(findJsonLeaks(JSON.parse(file)), [], 'parsed, the first member is gone');
  assert.ok(invariants.findFileLeaks(file).length > 0);
  assert.ok(invariants.findFileLeaks(`{"a":1,"a":2}`).length > 0);
  assert.deepEqual(invariants.findFileLeaks(`{"requestHeaders":{"Cookie":["${MASK}"]},"runs":[{"a":1},{"a":2}]}`), []);
  assert.ok(invariants.findFileLeaks('{"responseBody":"client_secret=s3cr3t"}').length > 0);
});

test('automated review r1: a JWK that a decoding shows with a repeated private member is flagged', () => {
  const B = '\\';
  assertFlagged(`{"kty":"RSA","d${B}${B}":"s3cr3t","d":"${MASK}"}`);
  assertFlagged(JSON.stringify({ body: `{"kty":"RSA","d${B}${B}":"s3cr3t","d":"${MASK}"}` }));
  assertFlagged(`{"keys":[{"kty":"oct","k${B}${B}":"s3cr3t","k":null}]}`);
  assertAccepted(`{"kty":"RSA","d${B}${B}":"${MASK}","d":"${MASK}"}`);
});

test('automated review r1: a private member a decoding shows must be the mask to where its value ends', () => {
  const B = '\\';
  assertFlagged(`{"kty":"RSA","d${B}${B}":"${MASK}${B}"FAKE-rest-0001"}`);
  assertFlagged(`{"kty":"RSA","d${B}${B}":"${MASK}${B}"FAKE-rest-0001","n":"N"}`);
  assertFlagged(`{"kty":"RSA","d${B}${B}":"null FAKE-rest-0001"}`);
});

test('one shared terminator: a masked value ends only at a terminator, whatever masks stand behind it, for every rule and entry point', () => {
  // Owner decision 3 on #425 (review r1 and r3, one family): one predicate decides where a masked value ends for every
  // rule. Masks behind the value's own must themselves run to the end of the text or to a terminator.
  const B = '\\';
  const REST = 'FAKE-rest-0001';
  const member = [',', '}', ']', ' ', '\n'];
  const RULES = [
    { rule: 'quoted member', head: `x "password":"${MASK}"`, terminators: member },
    { rule: 'member quoted with escaped quotes', head: `x ${B}"password${B}":${B}"${MASK}${B}"`, terminators: member },
    { rule: 'null member', head: 'x "password":null', terminators: member, noMasksBehind: true },
    { rule: 'scheme', head: `rejected Bearer ${MASK}`, terminators: [' ', '"', ',', ';', ')'] },
    { rule: 'form value', head: `sent client_secret=${MASK}`, terminators: ['&x=1', ' ', '"'] },
    { rule: 'header line', head: `Cookie: ${MASK}`, terminators: ['\nnext'] },
    // Rules that read no value still write a mask (decision 3, implementation note): none is exempt.
    { rule: 'JWT signature', head: `sent eyJhbGciOiJub25lIn0.eyJzdWIiOiJmYWtlIn0.${MASK}`, terminators: [' ', '"', ',', '.'] },
    { rule: 'mask to the end of a text', head: `payer said: ${MASK}`, terminators: [' ', '"', ',', '.'] },
    { rule: 'mask in a JSON string', json: (masks, follow) => JSON.stringify({ note: `payer said: ${MASK}${masks}${follow}` }), terminators: [' ', ','] },
    // A private member that only a decoding shows: what follows its value sits behind an escaped quote.
    { rule: 'private member in a decoding', json: (masks, follow) => `{"kty":"RSA","d${B}${B}":"${MASK}${follow === '' && masks === '' ? '' : `${B}"${masks}${follow}`}"}`, terminators: [] },
  ];
  /** As a recorded string, as a bundle file's text, and inside a bundle file (parsed, or as a line of a report value). */
  const entryPoints = text => {
    let parsed;
    try {
      parsed = { value: JSON.parse(text) };
    } catch {
      // Not JSON: judged as a line of a report value instead.
    }
    // Outside the catch: a check that throws on a parsed value fails the test.
    const third = findJsonLeaks(parsed ? parsed.value : { evidence: [`lead\n${text}\ntail`] });
    return [findTextLeaks(text), invariants.findFileLeaks(text), third].map(leaks => leaks.length > 0);
  };
  const wrong = [];
  let judged = 0;
  for (const { rule, head, json, terminators, noMasksBehind } of RULES) {
    for (const behind of noMasksBehind ? [0] : [0, 1, 2]) {
      for (const [follow, expected] of [['', false], ...terminators.map(t => [t, false]), [REST, true], [`${REST} more`, true], [`:${REST}`, true]]) {
        const masks = MASK.repeat(behind);
        const text = json ? json(masks, follow) : `${head}${masks}${follow}`;
        judged++;
        const verdicts = entryPoints(text);
        if (verdicts.some(flag => flag !== expected)) wrong.push(`${rule}, ${behind} masks behind, then ${JSON.stringify(follow)}: ${verdicts}, expected ${expected}`);
      }
    }
  }
  assert.ok(judged >= 10 * 2 * 3, `${judged} forms judged`);
  assert.deepEqual(wrong, []);
});

test('decision 6: in a decoding that is not JSON, a key-type member anywhere means every private member anywhere is the mask', () => {
  const B = '\\';
  const entryPoints = text => [findTextLeaks(text), invariants.findFileLeaks(text), findJsonLeaks(JSON.parse(text))].map(leaks => leaks.length > 0);
  const wrong = [];
  let judged = 0;
  // A private member that two decodings show (its name ends in a backslash), with a value that keeps the decoding from
  // being JSON. Beside it: a string that holds delimiters, also ones that do not pair, and ones a decoding bares.
  const STRINGS = ['}', '{', ']', '[', '}}', '{"a":1}', `${B}"}`, `}${B}"`, '},{', '{]', '[}', ']{', '}[', '{]}[',
    `${B}"{]${B}"`, `${B}"[}${B}"`, `${B}"]{${B}"`];
  // Where the private member stands relative to the key-type member: no bounds are read, so every place counts.
  const PLACES = {
    'the same object': (kty, note, priv) => order => `{${rotate([kty, note, priv], order).join(',')}}`,
    'an object beside a value that reads': (kty, note, priv) => order => `{${rotate([kty, note, '"sub":{"a":[1,{"b":2}]}', priv], order).join(',')}}`,
    'a nested object': (kty, note, priv) => order => `{${rotate([kty, note, `"sub":{"a":1,${priv}}`], order).join(',')}}`,
    'a nested list': (kty, note, priv) => order => `{${rotate([kty, note, `"sub":[{${priv}}]`], order).join(',')}}`,
    'a sibling object': (kty, note, priv) => order => `[${rotate([`{${kty}}`, `{${note}}`, `{${priv}}`], order).join(',')}]`,
    'the key type nested': (kty, note, priv) => order => `{${rotate([`"jwk":{${kty}}`, note, priv], order).join(',')}}`,
  };
  const rotate = (items, by) => [...items.slice(by % items.length), ...items.slice(0, by % items.length)];
  for (const [place, build] of Object.entries(PLACES)) {
    for (const inString of STRINGS) {
      for (const member of ['d', 'p', 'k', 'oth']) {
        for (const [value, expected] of [[`FAKE-jwk-0002${B}"rest`, true], [`${MASK}${B}"FAKE-jwk-0002`, true], [MASK, false]]) {
          for (const order of [0, 1, 2]) {
            const text = build(`"kty":"RSA"`, `"note":${JSON.stringify(inString)}`, `"${member}${B}${B}":"${value}"`)(order);
            JSON.parse(text);
            judged++;
            const verdicts = entryPoints(text);
            if (verdicts.some(flag => flag !== expected)) wrong.push(`${place}, ${JSON.stringify(inString)} ${member} order ${order} ${expected}: ${verdicts}`);
          }
        }
      }
    }
  }
  assert.ok(judged >= 6 * 17 * 4 * 3 * 3, `${judged} forms judged`);
  assert.deepEqual(wrong.slice(0, 40), [], `${wrong.length} of ${judged} wrong`);
  // Without a key-type member, a private member's name is any name.
  for (const build of Object.values(PLACES)) {
    assert.deepEqual(entryPoints(build(`"alg":"RS256"`, `"note":"}"`, `"d${B}${B}":"2026-11-04${B}"rest"`)(0)), [false, false, false]);
  }
  // A value that reads as JSON whole, in a decoding that does not: read as JSON only when no key-type member stands
  // outside such values.
  const breaks = `"note${B}${B}":"x${B}"y"`;
  for (const member of ['d', 'p', 'k', 'oth']) {
    for (const sub of [`{"${member}":"FAKE-jwk-0003"}`, `[{"a":{"${member}":"FAKE-jwk-0003"}}]`, `{"jwk":{"kty":"oct"},"data":{"${member}":"FAKE-jwk-0003"}}`]) {
      for (const order of [0, 1, 2]) {
        const outside = `{${rotate([`"kty":"RSA"`, breaks, `"sub":${sub}`], order).join(',')}}`;
        assert.deepEqual(entryPoints(outside), [true, true, true], `key type outside the value, order ${order}: ${sub}`);
        const none = `{${rotate([`"alg":"RS256"`, breaks, `"sub":${sub}`], order).join(',')}}`;
        assert.deepEqual(entryPoints(none), [false, false, false], `no key type outside the value, order ${order}: ${sub}`);
      }
    }
    const masked = `{"kty":"RSA",${breaks},"sub":{"${member}":"${MASK}"}}`;
    assert.deepEqual(entryPoints(masked), [false, false, false], `masked: ${member}`);
  }
});

test('decision 7: in a recorded string, a private member counts unless it sits in the same value as every key-type member', () => {
  const entryPoints = text => [findTextLeaks(text), invariants.findFileLeaks(JSON.stringify({ body: text })), findJsonLeaks({ body: text })].map(leaks => leaks.length > 0);
  const KEY = '{"kty":"RSA","n":"N1"}';
  const wrong = [];
  let judged = 0;
  const expect = (text, expected, label) => {
    for (const form of [text, JSON.stringify(text), JSON.stringify({ report: text })]) {
      judged++;
      const verdicts = entryPoints(form);
      if (verdicts.some(flag => flag !== expected)) wrong.push(`${label}, expected ${expected}: ${verdicts}`);
    }
  };
  for (const member of ['d', 'p', 'k', 'oth']) {
    for (const lead of ['payer said: ', '', 'a [list] first: ']) {
      const other = value => `{"${member}":"${value}"}`;
      // The key type in one value that reads, the private member in another, in either order, or in a list of its own.
      expect(`${lead}${KEY} and ${other('FAKE-jwk-0005')}`, true, `${member} in a value after the key's`);
      expect(`${lead}${other('FAKE-jwk-0005')} and ${KEY}`, true, `${member} in a value before the key's`);
      expect(`${lead}${KEY} and [${other('FAKE-jwk-0005')}]`, true, `${member} in a list after the key's`);
      // Two key types in two values: no one value holds them all, so a private member in either counts.
      expect(`${lead}${KEY} and {"jwk":${KEY},"data":${other('FAKE-jwk-0005')}}`, true, `${member} beside one of two key types`);
      // Masked, or no key type in the string.
      expect(`${lead}${KEY} and ${other(MASK)}`, false, `${member} masked`);
      expect(`${lead}{"alg":"RS256"} and ${other('2026-11-04')}`, false, `${member} with no key type`);
      // In the one value that holds every key type, the tree decides: outside the key's own object it is any name.
      expect(`${lead}{"jwk":${KEY},"data":${other('2026-11-04')}}`, false, `${member} in the value that holds the key type`);
      expect(`${lead}{"keys":[${KEY},${KEY}],"data":${other('2026-11-04')}} and {"x":1}`, false, `${member} in the value that holds both key types`);
    }
  }
  assert.ok(judged >= 4 * 3 * 8 * 3, `${judged} forms judged`);
  assert.deepEqual(wrong.slice(0, 12), [], `${wrong.length} of ${judged} wrong`);
});

test('decisions 3 and 7, one normal form: the per-string rule reads a name however it is spelled, at every decoding', () => {
  const entryPoints = text => [findTextLeaks(text), invariants.findFileLeaks(JSON.stringify({ body: text })), findJsonLeaks({ body: text })].map(leaks => leaks.length > 0);
  // A value with one of its member names spelled plainly, with a JSON escape, or a level down (its quotes escaped).
  const SPELLINGS = {
    plain: (json, name) => json,
    escaped: (json, name) => json.replace(`"${name}"`, `"\\u${name.charCodeAt(0).toString(16).padStart(4, '0')}${name.slice(1)}"`),
    'a level down': (json, name) => JSON.stringify(json).slice(1, -1),
    'escaped, a level down': (json, name) => JSON.stringify(SPELLINGS.escaped(json, name)).slice(1, -1),
  };
  const PLACEMENTS = {
    'a value after the key': (key, other) => `payer said: ${key} and ${other}`,
    'a value before the key': (key, other) => `payer said: ${other} and ${key}`,
    'a list after the key': (key, other) => `payer said: ${key} and [${other}]`,
    'a value after two keys': (key, other) => `${key} then ${key} and ${other}`,
  };
  const wrong = [];
  let judged = 0;
  for (const member of ['d', 'p', 'k', 'oth']) {
    for (const [keySpelling, spellKey] of Object.entries(SPELLINGS)) {
      for (const [otherSpelling, spellOther] of Object.entries(SPELLINGS)) {
        for (const [placement, place] of Object.entries(PLACEMENTS)) {
          // Masked: accepted where both values read at the string's own level. A value a level down does not read
          // there, and invariant 4 flags a JSON-looking start that does not parse in front of these names.
          const down = `${keySpelling}${otherSpelling}`.includes('level down');
          for (const [value, expected] of [['FAKE-jwk-0006', true], ...(down ? [] : [[MASK, false]])]) {
            const text = place(spellKey('{"kty":"RSA","n":"N1"}', 'kty'), spellOther(`{"${member}":"${value}"}`, member));
            judged++;
            const verdicts = entryPoints(text);
            if (verdicts.some(flag => flag !== expected)) wrong.push(`${member}: key ${keySpelling}, member ${otherSpelling}, ${placement}, expected ${expected}: ${verdicts}`);
          }
        }
      }
    }
  }
  assert.ok(judged >= 4 * 4 * 4 * 4 + 4 * 2 * 2 * 4, `${judged} forms judged`);
  assert.deepEqual(wrong.slice(0, 12), [], `${wrong.length} of ${judged} wrong`);
  // In the one value that holds every key type, the tree decides, however the names are spelled.
  for (const spell of [SPELLINGS.plain, SPELLINGS.escaped]) {
    const value = spell(spell('{"jwk":{"kty":"RSA","n":"N1"},"data":{"d":"2026-11-04"}}', 'kty'), 'd');
    assert.deepEqual(entryPoints(`payer said: ${value}`), [false, false, false], value);
  }
});

test('decision 8a: a secret-named key in object-literal spelling is read as a key, at every entry point', () => {
  const entryPoints = text => [findTextLeaks(text), invariants.findFileLeaks(JSON.stringify({ responseBody: text })), findJsonLeaks({ responseBody: text })].map(leaks => leaks.length > 0);
  const NAMES = ['client_secret', 'clientSecret', 'access_token', 'refresh_token', 'id_token', 'password', 'api_key', 'apiKey', 'private_key', 'Cookie', 'X-Api-Key'];
  const wrong = [];
  let judged = 0;
  for (const name of NAMES) {
    for (const [spelling, key] of [['unquoted', name], ['quoted', `"${name}"`]]) {
      for (const [space, lead] of [['', ''], [' ', ''], ['', 'config = '], ['\n  ', 'payer said: ']]) {
        // Masked: accepted on one line. At a line start a header name is a header line, whose value the Redactor masks.
        for (const [value, expected] of [['FAKE-literal-0001', true], ...(space.includes('\n') ? [] : [[MASK, false]])]) {
          const text = `${lead}{${space}${key}: "${value}"}`;
          judged++;
          const verdicts = entryPoints(text);
          if (verdicts.some(flag => flag !== expected)) wrong.push(`${name} ${spelling}, ${JSON.stringify(lead + space)}, expected ${expected}: ${verdicts}`);
        }
      }
    }
  }
  assert.ok(judged >= 11 * 2 * (4 + 3), `${judged} forms judged`);
  assert.deepEqual(wrong.slice(0, 12), [], `${wrong.length} of ${judged} wrong`);
  // A name that is no secret name is any key.
  assert.deepEqual(entryPoints('{note: "FAKE-literal-0001"}'), [false, false, false]);
});

test('decision 9: an object-literal key is read at every decoding, and through any whitespace the loose-key rule accepts', () => {
  const entryPoints = text => [findTextLeaks(text), invariants.findFileLeaks(JSON.stringify({ responseBody: text })), findJsonLeaks({ responseBody: text })].map(leaks => leaks.length > 0);
  const NAMES = ['client_secret', 'access_token', 'password', 'apiKey', 'private_key'];
  const u = c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`;
  const down = text => JSON.stringify(text).slice(1, -1);
  // The key as a decoding shows it: one of its characters, or all of the text, spelled with JSON escapes.
  const DECODINGS = {
    'the brace escaped': (name, value) => `${u('{')}${name}: "${value}"}`,
    'a letter of the name escaped': (name, value) => `{${u(name[0])}${name.slice(1)}: "${value}"}`,
    'the last letter of the name escaped': (name, value) => `{${name.slice(0, -1)}${u(name.at(-1))}: "${value}"}`,
    'the colon escaped': (name, value) => `{${name}${u(':')} "${value}"}`,
    'the value\'s quotes escaped': (name, value) => `{${name}: ${u('"')}${value}${u('"')}}`,
    'the value\'s quotes backslashed': (name, value) => `{${name}: \\"${value}\\"}`,
    'a level down': (name, value) => down(`{${name}: "${value}"}`),
    'two levels down': (name, value) => down(down(`{${name}: "${value}"}`)),
    'every character escaped': (name, value) => [...`{${name}: "`].map(u).join('') + value + u('"') + u('}'),
    'the brace escaped twice': (name, value) => `${down(u('{'))}${name}: "${value}"}`,
  };
  const CONTEXTS = {
    'the whole text': text => text,
    'after prose': text => `payer said: ${text} and more`,
    'in a string of a JSON text': text => JSON.stringify({ note: text, n: 1 }),
    'after a value that reads': text => `{"a":1} then ${text}`,
  };
  const wrong = [];
  let judged = 0;
  for (const name of NAMES) {
    for (const [decoding, spell] of Object.entries(DECODINGS)) {
      for (const [context, place] of Object.entries(CONTEXTS)) {
        judged++;
        const verdicts = entryPoints(place(spell(name, 'FAKE-literal-0002')));
        if (verdicts.some(flag => !flag)) wrong.push(`${name}, ${decoding}, ${context}: ${verdicts}`);
      }
    }
  }
  assert.ok(judged >= 5 * 10 * 4, `${judged} decoded forms judged`);
  assert.deepEqual(wrong.slice(0, 12), [], `${wrong.length} of ${judged} decoded forms wrong`);

  // One whitespace policy for recognizing the key and for judging it: what the loose-key rule accepts around a
  // separator, between the brace, the key, the colon and the value.
  const SPACES = [' ', '\t', '\n', '\r', '\u000b', '\f', '\u0085', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', '　', '﻿', ' \t ', '  '];
  const PLACES = {
    'after the brace': (name, ws, value) => `{${ws}${name}: "${value}"}`,
    'before the colon': (name, ws, value) => `{${name}${ws}: "${value}"}`,
    'after the colon': (name, ws, value) => `{${name}:${ws}"${value}"}`,
    'everywhere': (name, ws, value) => `{${ws}${name}${ws}:${ws}"${value}"${ws}}`,
  };
  const spaced = [];
  let spacedJudged = 0;
  for (const name of NAMES) {
    for (const ws of SPACES) {
      for (const [place, build] of Object.entries(PLACES)) {
        spacedJudged++;
        const verdicts = entryPoints(build(name, ws, 'FAKE-literal-0003'));
        if (verdicts.some(flag => !flag)) spaced.push(`${name}, ${JSON.stringify(ws)} ${place}: ${verdicts}`);
        // Masked, the same form is one the check accepts.
        const masked = entryPoints(build(name, ws, MASK));
        if (masked.some(flag => flag)) spaced.push(`${name}, ${JSON.stringify(ws)} ${place}, masked: ${masked}`);
      }
    }
  }
  assert.ok(spacedJudged >= 5 * 19 * 4, `${spacedJudged} spaced forms judged`);
  assert.deepEqual(spaced.slice(0, 12), [], `${spaced.length} of ${2 * spacedJudged} spaced forms wrong`);
  // Scope as decided: the key first after the brace, its value in double quotes.
  assert.deepEqual(entryPoints('{note: 1, password: "FAKE-literal-0003"}'), [false, false, false]);
});

test('decision 8c: a recorded text that ends in a masked quoted secret member is accepted inside a bundle file too', () => {
  const B = '\\';
  const inFile = text => [findTextLeaks(text), invariants.findFileLeaks(JSON.stringify({ responseBody: text })), findJsonLeaks({ responseBody: text }),
    invariants.findFileLeaks(JSON.stringify({ runs: [{ evidence: [text], status: 200 }] }))].map(leaks => leaks.length > 0);
  const wrong = [];
  let judged = 0;
  for (const name of ['client_secret', 'password', 'access_token', 'Authorization']) {
    const masked = name === 'Authorization' ? `Bearer ${MASK}` : MASK;
    for (const lead of ['{', 'note {', '{"a":1,', 'x ', '[{"a":"b"},{']) {
      for (const [value, behind, expected] of [[masked, '', false], [masked, MASK, false], [masked, 'FAKE-rest-0002', true], ['FAKE-rest-0002', '', true]]) {
        const text = `${lead}"${name}":"${value}"${behind}`;
        judged++;
        const verdicts = inFile(text);
        if (verdicts.some(flag => flag !== expected)) wrong.push(`${name} after ${JSON.stringify(lead)}, ${value} ${behind}, expected ${expected}: ${verdicts}`);
      }
    }
  }
  assert.ok(judged >= 4 * 5 * 4, `${judged} forms judged`);
  assert.deepEqual(wrong.slice(0, 12), [], `${wrong.length} of ${judged} wrong`);
  // A level further down the closing quote is a string's inside a recorded text: the Redactor masks that text.
  assert.deepEqual(inFile(`{"note":"x${B}"password${B}":${B}"${MASK}${B}""}`), [true, true, true, true]);
});

test('shares no code with the Redactor: the check imports nothing', () => {
  const source = readFileSync(here('./invariants.mjs'), 'utf8');
  assert.doesNotMatch(source, /^\s*import\b|\bimport\s*\(|\brequire\s*\(/m);
});

// ---------------------------------------------------------------------------------------------------------------------
// Class-level check (#160): generated secrets of every shape, placed in headers, bodies and query strings (see
// secret-cases.mjs), must be flagged both unmasked and where a mask stops short of their end. RedactorPropertyTest
// runs the same generator against the Redactor. A failure names its seed; LEAKS_SEED=<seed> reproduces it.

const SEED = Number(process.env.LEAKS_SEED ?? Math.floor(Math.random() * 2 ** 32));
const CASES = generateCases(SEED, 3000);
const describeCase = c => `seed ${SEED}: ${c.slot} ${c.secret.shape} ${c.encoding}${c.wrap === 'NONE' ? '' : ` in ${c.wrap}`} (${c.carrier}) after ${JSON.stringify(c.separator)}`;

/** Flagged in the slot's own text, as in a report, and in the recorded exchange, as in the bundle. */
const placementFlagged = ({ text, record }) => (text === null || flagged(text)) && findJsonLeaks(record).length > 0;

test('class-level check: flags every generated secret left unmasked', () => {
  for (const c of CASES) {
    const placement = build(c, placed(c));
    assert.ok(placementFlagged(placement), `${describeCase(c)} not flagged: ${placement.text ?? JSON.stringify(placement.record)}`);
  }
});

test('class-level check: flags a mask that stops short of a generated secret', () => {
  for (const c of CASES) {
    const value = placed(c);
    // Base64 lines without their armor can't be told from other text; the Redactor masks key blocks whole.
    if ((c.secret.shape === 'PEM' && c.encoding === 'RAW') || value.length <= PIECE) continue;
    const placement = build(c, MASK + value.slice(1 + (c.cut % (value.length - PIECE))));
    assert.ok(placementFlagged(placement), `${describeCase(c)} not flagged: ${placement.text ?? JSON.stringify(placement.record)}`);
  }
});

// ---------------------------------------------------------------------------------------------------------------------
// The Redactor's committed outputs (#425 criteria 2 and 3). Each scanner grid holds [input, Redactor output] pairs;
// RedactorTest fails when a file no longer matches the Redactor, and -Dredactor.grids.update=true rewrites it. The
// publish job runs this suite with no Maven build, so it reads the committed files, never target/ (#357).

const GRID_DIR = '../../workbench-core/src/test/resources/scanner-grids/';

/** The [input, output] pairs of a committed scanner grid. */
function grid(name) {
  return JSON.parse(gunzipSync(readFileSync(here(`${GRID_DIR}${name}.json.gz`))).toString('utf8'));
}

/** A string's content as Jackson's JsonStringEncoder writes it: short escapes, else \u00XX in upper case below 0x20. */
function jacksonQuoted(text) {
  const short = { 0x08: '\\b', 0x09: '\\t', 0x0a: '\\n', 0x0c: '\\f', 0x0d: '\\r', 0x22: '\\"', 0x5c: '\\\\' };
  let out = '';
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (short[c]) out += short[c];
    else if (c < 0x20) out += `\\u${c.toString(16).toUpperCase().padStart(4, '0')}`;
    else out += text[i];
  }
  return out;
}

/**
 * `text` as the Redactor writes a text it masks nothing in: each JSON string literal as Jackson's encoder writes it,
 * every character outside string literals as it is. Written apart from the Redactor and from the check. Text that is
 * one JSON value whose first character after JSON whitespace opens an object, an array or a string is rewritten, a
 * literal's content the same way first, to the Redactor's 8 levels; any other text has the JSON values embedded in it
 * rewritten (embeddedCanonical).
 */
function canonical(text, level = 0) {
  if (level >= 8) return text;
  if (!/^[ \t\n\r]*[[{"]/.test(text)) return embeddedCanonical(text, level);
  try {
    JSON.parse(text);
  } catch {
    return embeddedCanonical(text, level);
  }
  let out = '';
  let i = 0;
  while (i < text.length) {
    if (text[i] !== '"') {
      out += text[i++];
      continue;
    }
    let end = i + 1;
    while (text[end] !== '"') end += text[end] === '\\' ? 2 : 1;
    out += `"${jacksonQuoted(canonical(JSON.parse(text.slice(i, end + 1)), level + 1))}"`;
    i = end + 1;
  }
  return out;
}

/**
 * `text`, not one JSON value, with each JSON object or array in it written as `canonical` writes it. A value starts
 * at a bracket that no value read before it holds and runs to its matching bracket, quotes respected; JSON.parse must
 * read it. The walks to find the ends of candidates that do not read stop after about four times the text's length.
 */
function embeddedCanonical(text, level) {
  let out = '';
  let copied = 0;
  let budget = 4 * text.length + 4096;
  for (let i = 0; i < text.length && budget > 0; i++) {
    if (text[i] !== '{' && text[i] !== '[') continue;
    let depth = 0;
    let inString = false;
    let end = -1;
    for (let k = i; k < text.length && budget > 0; k++, budget--) {
      const c = text[k];
      if (inString) {
        if (c === '\\') k++;
        else if (c === '"') inString = false;
      } else if (c === '"') inString = true;
      else if (c === '{' || c === '[') depth++;
      else if ((c === '}' || c === ']') && --depth === 0) {
        end = k + 1;
        break;
      }
    }
    if (end < 0) continue;
    try {
      JSON.parse(text.slice(i, end));
    } catch {
      continue;
    }
    out += text.slice(copied, i) + canonical(text.slice(i, end), level);
    copied = end;
    i = end - 1;
  }
  return out + text.slice(copied);
}

/**
 * Each committed grid of current Redactor outputs with its row count and how many of its rows the Redactor masks (its
 * output is not the canonical spelling of its input). Pinned, so a grid that loses rows, or rows the Redactor stops
 * masking, fails here and not only in RedactorTest.
 */
const GRIDS = {
  'agreement-grid': [7135, 6214],
  'escape-chain-grid': [6765, 6765],
  'fail-closed-grid': [20690, 20690],
  'generic-separator-level-case-grid': [2560, 2560],
  'generic-separator-level-chain-grid': [7926, 7926],
  'generic-separator-level-cut-grid': [2880, 2880],
  'generic-separator-level-deeper-grid': [12780, 9930],
  'generic-separator-level-escape-grid': [16320, 16320],
  'generic-separator-level-flat-grid': [6400, 6400],
  'generic-separator-level-generated-grid': [16018, 15762],
  'generic-separator-level-loose-grid': [4900, 4900],
  'generic-separator-level-miss-grid': [2560, 2560],
  'generic-separator-level-name-grid': [2880, 2880],
  'generic-separator-level-over-grid': [1920, 1920],
  'generic-separator-level-probe-grid': [18200, 18200],
  'generic-separator-level-respelled-grid': [15100, 15100],
  'generic-separator-level-slice-grid': [2850, 2850],
  'generic-separator-level-spelled-grid': [6288, 6288],
  'generic-separator-level-spelling-grid': [4440, 4440],
  'generic-separator-level-whole-grid': [6440, 6440],
  'generic-separator-level-wrapped-grid': [14045, 14045],
  'generic-separator-miss-grid': [7437, 7365],
  'generic-separator-mixed-grid': [4200, 4120],
  'generic-separator-note-grid': [549, 549],
  'generic-separator-pin-grid': [57, 54],
  'jwk-search-budget-grid': [1500, 1383],
  'jwk-spelling-grid': [6946, 6946],
};

/**
 * agreement-main-grid holds the outputs of an earlier revision's Redactor (AgreementBaselineTest keeps it), not the
 * current one's, so criterion 3 does not apply to it; it is not read here.
 */
const NOT_CURRENT_OUTPUTS = ['agreement-main-grid'];

test('judges every committed scanner grid', () => {
  const committed = readdirSync(here(GRID_DIR)).map(file => file.replace(/\.json\.gz$/, '')).sort();
  assert.deepEqual(committed, [...Object.keys(GRIDS), ...NOT_CURRENT_OUTPUTS].sort());
  const totals = Object.values(GRIDS).reduce(([rows, masked], [r, m]) => [rows + r, masked + m], [0, 0]);
  assert.deepEqual(totals, [199_786, 195_487]);
});

for (const [name, [rows, masked]] of Object.entries(GRIDS)) {
  test(`flags every row the Redactor masks and accepts every Redactor output: ${name} (${rows} rows, ${masked} masked)`, () => {
    const pairs = grid(name);
    const missed = [];
    const outputsFlagged = [];
    let maskedRows = 0;
    for (const [input, out] of pairs) {
      if (out !== canonical(input)) {
        maskedRows++;
        if (!flagged(input)) missed.push(input);
      }
      const leaks = findTextLeaks(out);
      if (leaks.length > 0) outputsFlagged.push(`${leaks[0].check}: ${out}`);
    }
    assert.deepEqual([pairs.length, maskedRows], [rows, masked], 'rows, rows the Redactor masks');
    assert.deepEqual(missed.slice(0, 3), [], `${missed.length} of ${maskedRows} masked rows not flagged`);
    assert.deepEqual(outputsFlagged.slice(0, 3), [], `${outputsFlagged.length} of ${pairs.length} outputs flagged`);
  });
}

/**
 * Whether each entry point flags `text`: as a recorded string, as a string a bundle file holds, as a bundle file's
 * own text and, if it is JSON, as that file parsed.
 */
function verdicts(text) {
  const all = [flagged(text), findJsonLeaks({ responseBody: text }).length > 0, invariants.findFileLeaks(text).length > 0];
  let parsed;
  try {
    parsed = { value: JSON.parse(text) };
  } catch {
    // Not JSON: there is no parsed form to judge.
  }
  // Outside the catch: a check that throws on a parsed value fails the test.
  if (parsed) all.push(findJsonLeaks(parsed.value).length > 0);
  return all;
}

test('one choke point: every entry point gives the same verdict on every grid row, corpus entry and generated secret', () => {
  // Liaison decision on #425 (review r1 and r2, one family): a bundle file goes through the same path as a recorded
  // string, and the only file-specific difference is a credential header's list of masked values.
  const differ = [];
  let judged = 0;
  // A text is judged alike on its own and as a string a bundle file holds. As a bundle file itself it is judged
  // alike from its text and parsed; there each of its strings is a recorded text of its own (decision 8), so it may be
  // accepted where the text as one string is flagged, only when every string in it is accepted on its own.
  let asFileOnly = 0;
  const strings = value => (typeof value === 'string' ? [value] : value === null || typeof value !== 'object' ? []
    : Object.entries(value).flatMap(([name, member]) => [...(Array.isArray(value) ? [] : [name]), ...strings(member)]));
  const judge = text => {
    judged++;
    const [alone, held, ...asFile] = verdicts(text);
    if (alone !== held || asFile.some(verdict => verdict !== asFile[0])) differ.push(`${[alone, held, ...asFile]}: ${text.slice(0, 120)}`);
    else if (asFile[0] && !alone) differ.push(`flagged as a file only: ${text.slice(0, 120)}`);
    else if (asFile.length === 2 && alone && !asFile[0]) {
      asFileOnly++;
      if (strings(JSON.parse(text)).some(flagged)) differ.push(`accepted as a file with a flagged string: ${text.slice(0, 120)}`);
    }
    return alone;
  };
  for (const name of Object.keys(GRIDS)) {
    for (const [input, out] of grid(name)) {
      const masked = out !== canonical(input);
      if (judge(input) !== true && masked) differ.push(`masked row accepted: ${input.slice(0, 120)}`);
      if (judge(out) !== false) differ.push(`output flagged: ${out.slice(0, 120)}`);
    }
  }
  for (const e of corpus.text) if (!judge(e.input)) differ.push(`corpus entry accepted: ${e.id}`);
  for (const e of corpus.harmless) if (judge(e.input)) differ.push(`harmless entry flagged: ${e.id}`);
  for (const c of CASES) {
    const { text } = build(c, placed(c));
    if (text !== null && !judge(text)) differ.push(`generated secret accepted: ${describeCase(c)}`);
  }
  assert.ok(judged > 2 * 199_786, `${judged} texts judged`);
  assert.ok(asFileOnly <= 60, `${asFileOnly} texts accepted as a file of accepted strings`);
  assert.deepEqual(differ.slice(0, 5), [], `${differ.length} texts on which the entry points differ or are wrong`);
});

test('one choke point: the header list of masked values is the only thing a bundle file is allowed that a text is not', () => {
  const headers = JSON.stringify({ requestHeaders: { Cookie: [MASK], Authorization: [`Bearer ${MASK}`] } });
  assert.deepEqual(invariants.findFileLeaks(headers), []);
  assert.deepEqual(findJsonLeaks(JSON.parse(headers)), []);
  assert.ok(flagged(headers));
  // Inside a string of the file, the list is a recorded text's again.
  assert.ok(invariants.findFileLeaks(JSON.stringify({ responseBody: headers })).length > 0);
});

test('accepts the Redactor\'s output for the corpus and the seeded fuzz corpus, also as a bundle file holds it', () => {
  // The agreement grid: the Redactor's output for every text and harmless corpus entry (135), 5,000 seeded fuzz texts
  // and 2,000 with credential claims in their JWTs (RedactorTest.recordsItsOutputsForTheCorpusAndTheFuzzCorpus...).
  // Zero flags (the goal #377 moved to this stage), as a recorded string and inside a bundle file's structure; and
  // every raw input the Redactor masks is flagged in a bundle file as well.
  const pairs = grid('agreement-grid');
  assert.equal(pairs.length, 135 + 5_000 + 2_000);
  const wrong = [];
  for (const [input, out] of pairs) {
    if (findJsonLeaks({ steps: [{ details: { exchanges: [{ responseBody: out }] } }] }).length > 0) wrong.push(`output: ${out}`);
    if (out !== canonical(input) && findJsonLeaks({ responseBody: input }).length === 0) wrong.push(`input: ${input}`);
  }
  assert.deepEqual(wrong.slice(0, 3), [], `${wrong.length} wrong`);
});

test('the grid check fails for a masked row left unflagged and for a flagged output (the check on the check)', () => {
  // What the loop above would report if the check went blind or over-strict, on one real row of each kind.
  const [input, out] = grid('generic-separator-pin-grid').find(([i, o]) => o !== canonical(i));
  assert.notEqual(out, canonical(input));
  assert.ok(flagged(input));
  assert.deepEqual(findTextLeaks(out), []);
  // The input holds what the output lost: judging the pair the wrong way round finds a flagged "output".
  assert.ok(findTextLeaks(input).length > 0 && canonical(out) === out);
});

// ---------------------------------------------------------------------------------------------------------------------
// Work: a bundle file is megabytes of payer text, so every rule must read a long hostile text in about linear time.

const HOSTILE = {
  'object starts': n => '{'.repeat(n),
  'array starts': n => '['.repeat(n),
  'open names': n => '{"'.repeat(n / 2),
  'a backslash run': n => `x${'\\'.repeat(n)}`,
  'token runs': n => 'eyJ-'.repeat(n / 4),
  'token pieces': n => 'eyJhbGciOiJub25lIn0.'.repeat(n / 20),
  'scheme words': n => 'Bearer '.repeat(n / 7),
  'schemes before long whitespace': n => `Bearer${' '.repeat(50)}"`.repeat(n / 57),
  'a key before a long separator run': n => `client${'_'.repeat(n)}x`,
  'secret names in prose': n => 'password '.repeat(n / 9),
  'secret names before open lists': n => `${'"password":['.repeat(n / 12)}]`,
  'secret names before open strings': n => '"password":"'.repeat(n / 12),
  'a secret name before a list and long whitespace': n => `{"a":"x\\"Authorization\\":[\\"Bearer ${MASK}\\"${' '.repeat(n)}x"}`,
  'open quoted names': n => '"aaaaaaaa'.repeat(n / 9),
  'keys before long gaps': n => `password${'\\n'.repeat(20)}`.repeat(n / 48),
  'private names before backslashes': n => `"kty" ${'"d\\\\\\\\'.repeat(n / 6)}`,
  'armor starts': n => '-----BEGIN '.repeat(n / 11),
  'blank header lines': n => 'Cookie:\n'.repeat(n / 8),
  'masked form keys': n => `api_key=${MASK}&`.repeat(n / 19),
  'embedded values': n => 'log {"a":1} '.repeat(n / 12),
  'broken starts before masked keys': n => `{"password":"${MASK}" `.repeat(n / 25),
  'strings that spell kty': n => JSON.stringify(Array.from({ length: n / 30 }, (_, i) => ({ a: `kty${i}`, d: MASK }))),
  'deep arrays': n => `${'['.repeat(n / 2)}${']'.repeat(n / 2)}`,
  'whitespace before a brace in a decoding with a kty': n => `x\\n"kty" ${' '.repeat(n)}{} ${'{ '.repeat(8)}`,
  'whitespace runs after commas in a decoding with a kty': n => `x\\n"kty":1 ${`,${' '.repeat(200)}x`.repeat(n / 202)}`,
};

test('reads long hostile texts in work that grows with their length, not its square', () => {
  // 400,000 characters of each shape: linear work takes tens of milliseconds, quadratic work minutes. The bound is a
  // wide one on purpose, so a loaded host does not fail it.
  const slow = [];
  for (const [shape, make] of Object.entries(HOSTILE)) {
    const text = make(400_000);
    const start = performance.now();
    findTextLeaks(text);
    findJsonLeaks({ responseBody: text });
    const elapsed = performance.now() - start;
    if (elapsed > 10_000) slow.push(`${shape}: ${Math.round(elapsed)} ms`);
  }
  assert.deepEqual(slow, []);
});
