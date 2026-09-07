const { test } = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const crypto = require('node:crypto').webcrypto;

function load(fetch) {
    const timers = new Map();
    let next = 0;
    const context = {
        fetch, Response, FormData, AbortController, TextDecoder, crypto,
        console: { log() {} },
        setTimeout(fn, delay) { timers.set(++next, { fn, delay }); return next; },
        clearTimeout(id) { timers.delete(id); }
    };
    vm.runInNewContext(fs.readFileSync('www/js/nomorepass.js', 'utf8'), context);
    context.NomorePass.init({ apikey: 'test-key' });
    return { nmp: context.NomorePass, timers };
}
const flush = () => new Promise(resolve => setImmediate(resolve));

test('browser initial request preserves multipart, apikey and QR format', async () => {
    let options;
    const { nmp, timers } = load(async (url, config) => {
        options = config;
        assert.equal((await new Response(config.body).formData()).get('site'), 'café');
        return new Response('{"resultado":"ok","ticket":"TICKET"}');
    });
    const qr = await new Promise(resolve => nmp.getQrText('café', resolve));
    assert.match(qr, /^nomorepass:\/\/[a-zA-Z0-9]{12}TICKETcafé$/);
    assert.equal(options.headers.apikey, 'test-key');
    assert.equal(options.redirect, 'error');
    assert.equal(timers.size, 0);
});

for (const mode of ['post', 'postJson']) {
    for (const [name, response, expected] of [
        ['HTTP 400', () => new Response('bad', { status: 400 }), 'HTTP_400'],
        ['invalid JSON', () => new Response('{'), 'INVALID_JSON'],
        ['null JSON', () => new Response('null'), 'INVALID_JSON'],
        ['network failure', () => { throw new TypeError('network'); }, 'REQUEST_FAILED'],
        ['oversized response', () => new Response('x'.repeat(1048577)), 'RESPONSE_TOO_LARGE']
    ]) {
        test(`browser ${mode}: ${name} reports failure once`, async () => {
            const { nmp, timers } = load(async () => response());
            let calls = 0;
            const failure = data => { calls++; assert.equal(data.error, expected); };
            await nmp[mode]('/api', {}, mode === 'post' ? failure : () => assert.fail(), failure);
            assert.equal(calls, 1);
            assert.equal(timers.size, 0);
        });
    }
    test(`browser ${mode} rejects oversized encoded request before fetch`, async () => {
        const { nmp } = load(() => assert.fail('must not send'));
        await nmp[mode]('/api', { value: 'é'.repeat(524288) }, data => {
            assert.equal(data.error, 'REQUEST_TOO_LARGE');
        });
    });
}

for (const action of ['stop', 'init', 'deadline']) {
    test(`browser ${action} cancels initial request without stale callbacks`, async () => {
        let signal;
        const { nmp, timers } = load((url, options) => new Promise((resolve, reject) => {
            signal = options.signal;
            signal.addEventListener('abort', () => reject(new Error('aborted')));
        }));
        let calls = 0;
        nmp.getQrText('site', data => { calls++; assert.equal(data, false); });
        await flush();
        assert.ok(signal);
        if (action === 'deadline') {
            assert.equal([...timers.values()][0].delay, 15000);
            [...timers.values()][0].fn();
        } else nmp[action]();
        await flush();
        assert.equal(signal.aborted, true);
        assert.equal(calls, action === 'deadline' ? 1 : 0);
        assert.equal(timers.size, 0);
    });
}

test('browser deadline covers stalled response body', async () => {
    let options;
    const { nmp, timers } = load(async (url, config) => {
        options = config;
        return new Response(new ReadableStream({ start(controller) {
            controller.enqueue(new TextEncoder().encode('{'));
            config.signal.addEventListener('abort', () => controller.error(new Error('aborted')));
        } }));
    });
    let calls = 0;
    const request = nmp.post('/api', {}, data => { calls++; assert.equal(data.error, 'REQUEST_TIMEOUT'); });
    await flush();
    [...timers.values()][0].fn();
    await request;
    assert.equal(options.signal.aborted, true);
    assert.equal(calls, 1);
    assert.equal(timers.size, 0);
});

test('browser stop clears receive/send polling and init permits a new session', async () => {
    const { nmp, timers } = load(async () => new Response('{"resultado":"ok","grant":"pending"}'));
    nmp.start(() => assert.fail());
    nmp.send(() => assert.fail());
    await flush();
    assert.equal(timers.size, 2);
    nmp.stop();
    assert.equal(timers.size, 0);
    nmp.start(() => assert.fail());
    nmp.send(() => assert.fail());
    assert.equal(timers.size, 0);
    nmp.init();
    nmp.start(() => assert.fail());
    await flush();
    assert.equal(timers.size, 1);
    nmp.stop();
});

test('browser polling reports malformed responses through callback', async () => {
    const { nmp } = load(async () => new Response('invalid'));
    await new Promise(resolve => nmp.start((error, code) => {
        assert.equal(error, true);
        assert.equal(code, 'INVALID_JSON');
        resolve();
    }));
});

test('browser transport with real fetch rejects redirects and oversized compressed streams', async t => {
    const http = require('node:http');
    const { gzipSync } = require('node:zlib');
    let redirected = false;
    const server = http.createServer((req, res) => {
        req.resume();
        if (req.url === '/redirect') {
            res.writeHead(307, { Location: '/target' });
            res.end();
        } else if (req.url === '/target') {
            redirected = true;
            res.end('{}');
        } else if (req.url === '/large') {
            res.writeHead(200, { 'Content-Encoding': 'gzip' });
            res.end(gzipSync('x'.repeat(1048577)));
        } else {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.write('{"resultado":');
            res.end('"ok"}');
        }
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => { server.closeAllConnections(); server.close(); });
    const { nmp } = load(fetch);
    const url = `http://127.0.0.1:${server.address().port}`;
    for (const mode of ['post', 'postJson']) {
        await nmp[mode](url + '/ok', {}, data => assert.equal(data.resultado, 'ok'));
        await nmp[mode](url + '/redirect', {}, data => assert.equal(data.error, 'REQUEST_FAILED'));
        assert.equal(redirected, false);
        await nmp[mode](url + '/large', {}, data => assert.equal(data.error, 'RESPONSE_TOO_LARGE'));
    }
});
