const { test } = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const crypto = require('node:crypto');

function load(post) {
    const timers = new Map();
    let nextTimer = 0;
    const context = {
        exports: {}, AbortController, console,
        setTimeout(fn, delay) { timers.set(++nextTimer, { fn, delay }); return nextTimer; },
        clearTimeout(id) { timers.delete(id); },
        require(name) {
            if (name === 'axios') return { post };
            if (name === 'crypto') return crypto;
            if (name === 'crypto-js') return {};
            if (name === 'form-data') return class {
                append() {}
                getHeaders() { return {}; }
            };
            throw new Error(name);
        }
    };
    vm.runInNewContext(fs.readFileSync('lib/nomorepass.js', 'utf8'), context);
    context.exports.init({});
    return { nmp: context.exports, timers, context };
}
const flush = () => new Promise(resolve => setImmediate(resolve));

test('initial request has finite limits and protocol-compatible cryptographic token', async () => {
    let options;
    const { nmp, timers } = load(async (url, data, config) => {
        options = config;
        return { data: { resultado: 'ok', ticket: 'TICKET' } };
    });
    const qr = await new Promise(resolve => nmp.getQrText('site', resolve));
    assert.match(qr, /^nomorepass:\/\/[a-zA-Z0-9]{12}TICKETsite$/);
    assert.equal(options.timeout, 15000);
    assert.equal(options.maxContentLength, 1048576);
    assert.equal(options.maxBodyLength, 1048576);
    assert.equal(options.maxRedirects, 3);
    assert.equal(options.signal.aborted, false);
    await flush();
    assert.equal(timers.size, 0);
});

for (const action of ['stop', 'init', 'deadline']) {
    test(`${action} aborts the first request and cleans its deadline`, async () => {
        let signal;
        let result = 'not called';
        const { nmp, timers } = load((url, data, options) => new Promise((resolve, reject) => {
            signal = options.signal;
            signal.addEventListener('abort', () => reject({ code: 'ERR_CANCELED' }));
        }));
        nmp.getQrText('site', value => { result = value; });
        if (action === 'deadline') [...timers.values()][0].fn();
        else nmp[action]();
        await flush();
        assert.equal(signal.aborted, true);
        assert.equal(result, action === 'deadline' ? false : 'not called');
        assert.equal(timers.size, 0);
    });
}

test('transport failure reaches the polling callback', async () => {
    const { nmp, timers } = load(async () => { throw { code: 'ERR_BAD_RESPONSE' }; });
    const result = await new Promise(resolve => nmp.start((error, data) => resolve([error, data])));
    assert.deepEqual(result, [true, 'ERR_BAD_RESPONSE']);
    await flush();
    assert.equal(timers.size, 0);
});

test('stop clears scheduled polling', async () => {
    const { nmp, timers } = load(async () => ({ data: { resultado: 'ok', grant: 'pending' } }));
    nmp.start(() => assert.fail('unexpected callback'));
    await flush();
    assert.equal(timers.size, 1);
    nmp.stop();
    assert.equal(timers.size, 0);
});

test('browser token rejects biased byte values and uses Web Crypto', () => {
    const context = { crypto: { getRandomValues(bytes) { bytes.fill(255); bytes[0] = 61; } } };
    vm.runInNewContext(fs.readFileSync('www/js/nomorepass.js', 'utf8'), context);
    assert.equal(context.NomorePass.newtoken(), '999999999999');
    delete context.crypto;
    assert.throws(() => context.NomorePass.newtoken());
});
