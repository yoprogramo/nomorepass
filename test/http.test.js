const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const nmp = require('../lib/nomorepass');

test('real Axios enforces response, body, redirect and cancellation limits', async t => {
    let requests = 0;
    let stalled;
    const server = http.createServer((req, res) => {
        requests++;
        req.resume();
        if (req.url === '/large') res.end('x'.repeat(1048577));
        else if (req.url === '/redirect') {
            res.writeHead(307, { Location: '/redirect' });
            res.end();
        } else if (req.url === '/stall') stalled();
        else res.end(JSON.stringify({ resultado: 'ok', ticket: 'TICKET' }));
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => { nmp.stop(); server.closeAllConnections(); server.close(); });
    const url = `http://127.0.0.1:${server.address().port}`;
    const qr = site => new Promise(resolve => nmp.getQrText(site, resolve));
    nmp.init({ getidUrl: url + '/ok' });
    assert.match(await qr('site'), /^nomorepass:\/\/[a-zA-Z0-9]{12}TICKETsite$/);
    nmp.init({ getidUrl: url + '/large' });
    assert.equal(await qr('site'), false);
    nmp.init({ getidUrl: url + '/redirect' });
    requests = 0;
    assert.equal(await qr('site'), false);
    assert.equal(requests, 4);
    nmp.init({ getidUrl: url + '/ok' });
    assert.equal(await qr('x'.repeat(1048577)), false);
    nmp.init({ getidUrl: url + '/stall' });
    await new Promise(resolve => {
        stalled = resolve;
        nmp.getQrText('site', () => assert.fail('callback after stop'));
    });
    nmp.stop();
});

test('real Axios terminates a stalled initial request', { timeout: 20000 }, async t => {
    const server = http.createServer(req => req.resume());
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => { nmp.stop(); server.closeAllConnections(); server.close(); });
    nmp.init({ getidUrl: `http://127.0.0.1:${server.address().port}/` });
    assert.equal(await new Promise(resolve => nmp.getQrText('site', resolve)), false);
});
