/* 
 * nomorepass.js : código para hacer las llamadas de autenticación pertinentes
 * 
 * Puro js, depende de CryptoJS.AES
 * 
 */

if (typeof CryptoJS != 'object'){
    console.log("CryptoJS should be loaded before");
}

if (typeof NomorePass === 'undefined') {
    
var NomorePass = {
    device: null,
    token: null,
    fielduser: "#user",
    fieldpass: "#password",
    fieldresp: null,
    callback: null,
    qrcode: "#qrcode",
    stopped: false,
    expiry: null,
    config: {},
    activeRequests: new Set(),
    pollingTimers: new Set(),
    schedulePoll: function (callback, delay) {
        if (NomorePass.stopped) return;
        var timer = setTimeout(function () {
            NomorePass.pollingTimers.delete(timer);
            callback();
        }, delay);
        NomorePass.pollingTimers.add(timer);
    },
    cancelPending: function () {
        for (var request of NomorePass.activeRequests) request.cancel();
        NomorePass.activeRequests.clear();
        for (var timer of NomorePass.pollingTimers) clearTimeout(timer);
        NomorePass.pollingTimers.clear();
    },
    init: function (config) {
        NomorePass.cancelPending();
        if (typeof config == 'object') {
            NomorePass.config = config;
        }
        if (!('getidUrl' in NomorePass.config))
            NomorePass.config.getidUrl = "https://nomorepass.com/api/getid.php";
        if (!('checkUrl' in NomorePass.config))
            NomorePass.config.checkUrl = "https://nomorepass.com/api/check.php";
        if (!('authUrl' in NomorePass.config))
            NomorePass.config.authUrl = "https://nomorepass.com/api/auth.php";
        if (!('assocUrl' in NomorePass.config))
            NomorePass.config.assocUrl = "https://nomorepass.com/api/assoc.php";
        if (!('pingUrl' in NomorePass.config))
            NomorePass.config.pingUrl = "https://nomorepass.com/api/ping.php";
        if (!('referenceUrl' in NomorePass.config))
            NomorePass.config.referenceUrl = "https://nomorepass.com/api/reference.php";
        if (!('grantUrl' in NomorePass.config))
            NomorePass.config.grantUrl = "https://nomorepass.com/api/grant.php";
        if (!('apikey' in NomorePass.config))
            NomorePass.config.apikey='FREEAPIKEY';
        NomorePass.stopped = false;
    },
    decrypt: function (password,token){
        var pass = CryptoJS.AES.decrypt(password, token).toString(CryptoJS.enc.Utf8);
        return pass;
    },
    newtoken: function () {
      var length = 12,
        charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        retVal = "";
        // Reject values above 247 to avoid bias when mapping bytes to base62.
        var bytes = new Uint8Array(32);
        while (retVal.length < length) {
            crypto.getRandomValues(bytes);
            for (var i = 0; i < bytes.length && retVal.length < length; ++i) {
                if (bytes[i] < 248) retVal += charset.charAt(bytes[i] % charset.length);
            }
        }
        return retVal;  
    },
    getQrText: function (site, callback) {
        // Protocolo 2 NMP
        // First, get Ticket
        let params = {
            "site": site
        };
        if (NomorePass.expiry!=null) {
            params['expiry'] = NomorePass.expiry;
        }
        NomorePass.post(NomorePass.config.getidUrl,params,
             function(data){
                if (data.resultado=='ok') {
                    var tk = NomorePass.newtoken();
                    NomorePass.token = tk;
                    NomorePass.ticket = data.ticket;
                    var text = 'nomorepass://'+tk+data.ticket+site;
                    if (typeof callback == 'function') {
                    callback(text);
                    }
                } else {
                    callback(false);
                }
            });
    },
    start: function (callback) {
        // Protocolo 2 NMP
        // Using ticket only
        NomorePass.check(callback);
    },
    check: function (callback) {
        if (NomorePass.stopped){
            return; // Execution stopped, not calling callback
        }
        NomorePass.post(NomorePass.config.checkUrl,{
            'ticket': NomorePass.ticket
        }, function(data){
           if (data.resultado=='ok') {
               if (data.grant=='deny') {
                   if (typeof callback == 'function') {
                       callback(true,'denied');
                   }
               } else {
                   if (data.grant=='grant') {
                       var data = {
                           user: data.usuario,
                           password: NomorePass.decrypt(data.password,NomorePass.token),
                           extra: data.extra};
                        if (typeof callback == 'function') {
                            callback(false,data);
                        }
                   } else {
                        if (data.grant=='expired') {
                            if (typeof callback == 'function') {
                                callback(true,'expired');
                            }
                        } else {
                            NomorePass.schedulePoll(function() {NomorePass.check(callback);}, 3000);
                        }
                   }
               }
           } else {
               if (typeof callback == 'function') callback(true, data.error || 'REQUEST_FAILED');
           }
        });
    },
    stop: function () {
        NomorePass.stopped = true;
        NomorePass.cancelPending();
    },
    getQrSend: function (site, user, pass, extra, callback) {
        // Protocol 2 reverse
        // First we made grant then ping
        if (site==null) {
            // site is the id device of origin, if null use generic WEBDEVICE
            site = "WEBDEVICE";
        }
        var device = "WEBDEVICE";
        NomorePass.post(NomorePass.config.referenceUrl,
            { 'device': device, 
              'fromdevice': device},
            function(response){
                if (response.resultado=='ok') {
                    var tokenfb = response.token;
                    let params = {
                        "site": site
                    };
                    if (NomorePass.expiry!=null) {
                        params['expiry'] = NomorePass.expiry;
                    }
                    NomorePass.post(NomorePass.config.getidUrl,params,
                    function(data){
                      if (data.resultado=='ok') {
                        var tk = NomorePass.newtoken();
                        NomorePass.token = tk;
                        NomorePass.ticket = data.ticket;
                        var ep = CryptoJS.AES.encrypt(pass, tk);
                        // Make the grant and return text
                        if (typeof extra == 'object') {
                            extra = JSON.stringify(extra);
                        }
                        NomorePass.post(NomorePass.config.grantUrl,{
                            'grant': 'grant',
                            'ticket': NomorePass.ticket,
                            'user' : user,
                            'password': ''+ep,
                            'extra': extra
                        }, function (resp){
                            if (resp.resultado=='ok') {
                                console.log("Granted");
                            } else {
                                console.log(response);
                            }
                        });
                        var text = 'nomorepass://SENDPASS'+tk+data.ticket+site;
                        if (typeof callback == 'function') {
                            callback(text);
                        }
                      } else {
                        if (typeof callback == 'function') {
                          callback(false);
                        }
                      }
                   });
                } else {
                    callback(false);
                }
            }
        );
    },
    getQrNomoreKeys: function (site, user, pass, type, extra, callback) {
        // Protocol 2 reverse
        // First we made grant then ping
        // for nomorekeys phisical keys (soundkey or lightkey)
        if (type!='SOUNDKEY' && type!='LIGHTKEY' && type!='BLEKEY')
            type='KEY';
        if (site==null) {
            // site is the id device of origin, if null use generic WEBDEVICE
            site = "WEBDEVICE";
        }
        var device = "WEBDEVICE";
        NomorePass.post(NomorePass.config.referenceUrl,
            { 'device': device, 
              'fromdevice': device},
            function(response){
                if (response.resultado=='ok') {
                    var tokenfb = response.token;
                    let params = {
                        "site": site
                    };
                    if (NomorePass.expiry!=null) {
                        params['expiry'] = NomorePass.expiry;
                    }
                    NomorePass.post(NomorePass.config.getidUrl,params,
                     function(data){
                      if (data.resultado=='ok') {
                        var tk = NomorePass.newtoken();
                        NomorePass.token = tk;
                        NomorePass.ticket = data.ticket;
                        if (type=='SOUNDKEY'){
                            pass = pass.substr(0,14).padEnd(14," ");
                        } else 
                            if (type=='LIGHTKEY') {
                            pass=""+parseInt(pass)%65536;
                        }
                        var ep = CryptoJS.AES.encrypt(pass, tk);
                        if (typeof extra == 'object') {
                            if ('extra' in extra) {
                                if (typeof extra['extra']=='object') {
                                    if ('secret' in extra['extra']) {
                                    extra['extra']['secret']=""+CryptoJS.AES.encrypt(extra['extra']['secret'],tk);
                                    }
                                    if (!('type' in extra['extra'])) {
                                        extra['extra']['type'] = type.toLowerCase();
                                    }
                                } else {
                                    extra['extra'] = {'type':type.toLowerCase()};
                                }
                            } else {
                                extra['extra'] = {'type':type.toLowerCase()};
                            }
                            if (!('type' in extra)) {
                                extra['type'] = type.toLowerCase();
                            }
                        } else {
                            extra = {'extra': {'type': type.toLowerCase()}};
                        }
                        extra = JSON.stringify(extra);
                        // Make the grant and return text
                        if (typeof extra == 'object') {
                            extra = JSON.stringify(extra);
                        }
                        NomorePass.post(NomorePass.config.grantUrl,{
                            'grant': 'grant',
                            'ticket': NomorePass.ticket,
                            'user' : user,
                            'password': ''+ep,
                            'extra': extra
                        }, function (resp){
                            if (resp.resultado=='ok') {
                                console.log("Granted");
                            } else {
                                console.log(response);
                            }
                        });
                        var text = 'nomorekeys://'+type+tk+data.ticket+site;
                        if (typeof callback == 'function') {
                            callback(text);
                        }
                      } else {
                        if (typeof callback == 'function') {
                          callback(false);
                        }
                      }
                   });
                } else {
                    callback(false);
                }
            }
        );
    },
    send: function (callback){
        var txt = "XXXXXXXXXXXX"+NomorePass.ticket;
        NomorePass.schedulePoll(function(){NomorePass.ping(txt,callback);},4000);
    },
    ping: function (data,callback){
        if (NomorePass.stopped){
            return;
        } else {
            var ticket=data.substring(12);
            NomorePass.post(NomorePass.config.pingUrl,{'device': 'WEBDEVICE', 
            ticket:ticket},function(data){
                if ((data.resultado=='ok') && (data.ping=='ok')) {
                  NomorePass.schedulePoll(function(){NomorePass.ping("XXXXXXXXXXXX"+ticket,callback)},4000);
                } else {
                   console.log(data);
                   if (typeof callback == 'function') {
                    callback(data);
                   }
                }
              });
        }
    },
    sendRemotePassToDevice: function (cloud,deviceid,secret,username,password,callback) {
        // Envía una contraseña remota a un dispositivo cloud
        // cloud: url de /extern/send_ticket 
        // devideid: id del dispositivo
        // secret: md5 del secreto del dispositivo
        // username: usuario
        // password: contraseña
        // callback función a llamar en caso de éxito
        let cloudurl = cloud;
        if (cloudurl==null)
            cloudurl="https://api.nmkeys.com/extern/send_ticket";
        let token = secret;
        let params = {
            "site": 'Send remote pass'
        };
        if (NomorePass.expiry!=null) {
            params['expiry'] = NomorePass.expiry;
        }
        NomorePass.post(NomorePass.config.getidUrl, params,
         function(data){
            if (data.resultado=='ok') {
                NomorePass.ticket = data.ticket;
                let ep = CryptoJS.AES.encrypt(password, token);
                NomorePass.post(NomorePass.config.grantUrl, {
                    'grant': 'grant', 
                    'ticket': NomorePass.ticket, 
                    'user': username, 
                    'password' : ''+ep, 
                    'extra': JSON.stringify({'type': 'remote'})
                }, function (data){
                    if (data.resultado=='ok') {
                        NomorePass.postJson(cloud,
                            {'hash': token.substring(0,10), 
                            'deviceid': deviceid, 
                            'ticket': NomorePass.ticket},
                            function (data) {
                                if (typeof callback == 'function')
                                    callback (data);
                            }, (data)=>{console.log(data)})
                    } else {
                        console.log (data);
                    }
                })
            } else {
                console.log (data);
            }
        })
    },
    // Keep the callback API, but read responses incrementally to bound buffering.
    request: function (url, makeBody, headers, callback, fail) {
        if (NomorePass.stopped) return Promise.resolve();
        var controller = new AbortController();
        var finished = false;
        var timer;
        var request = { cancel: function () { finish(null, true); } };
        function finish(data, cancelled, failed) {
            if (finished) return;
            finished = true;
            clearTimeout(timer);
            NomorePass.activeRequests.delete(request);
            controller.abort();
            if (!cancelled) {
                var handler = failed && typeof fail == 'function' ? fail : callback;
                if (typeof handler == 'function') handler(data);
            }
        }
        function failure(code) {
            finish({ resultado: 'error', status: 'ko', error: code }, false, true);
        }
        NomorePass.activeRequests.add(request);
        timer = setTimeout(function () { failure('REQUEST_TIMEOUT'); }, 15000);
        return (async function () {
            var result;
            var errorCode = 'REQUEST_FAILED';
            var reader;
            try {
                // Serialize multipart with its boundary before checking the wire size.
                var body = await new Response(makeBody()).blob();
                if (finished) return;
                if (body.size > 1024 * 1024) {
                    errorCode = 'REQUEST_TOO_LARGE';
                    throw new Error(errorCode);
                }
                var response = await fetch(url, {
                    method: 'POST', body: body, headers: headers,
                    signal: controller.signal, redirect: 'error', credentials: 'same-origin'
                });
                if (finished) return;
                if (!response.ok) {
                    errorCode = 'HTTP_' + response.status;
                    throw new Error(errorCode);
                }
                if (!response.body) throw new Error('Missing response stream');
                reader = response.body.getReader();
                var decoder = new TextDecoder();
                var text = '';
                var size = 0;
                while (true) {
                    var chunk = await reader.read();
                    if (finished) return;
                    if (chunk.done) break;
                    size += chunk.value.byteLength;
                    if (size > 1024 * 1024) {
                        errorCode = 'RESPONSE_TOO_LARGE';
                        throw new Error(errorCode);
                    }
                    text += decoder.decode(chunk.value, { stream: true });
                }
                text += decoder.decode();
                errorCode = 'INVALID_JSON';
                result = JSON.parse(text);
                if (result === null || typeof result !== 'object' || Array.isArray(result)) {
                    throw new Error('Expected a JSON object');
                }
            } catch (error) {
                failure(errorCode);
                return;
            } finally {
                if (reader) {
                    // Do not wait for a remote stream to acknowledge cancellation.
                    reader.cancel().catch(function () {});
                    reader.releaseLock();
                }
            }
            // User callback exceptions must not trigger a second failure callback.
            finish(result, false, false);
        })();
    },
    post : function (url,params,callback) {
        return NomorePass.request(url, function () {
            var formData = new FormData();
            for (var name in params) formData.append(name, params[name]);
            return formData;
        }, { apikey: NomorePass.config.apikey }, callback);
    },
    postJson : function (url,params,callback,fail) {
        return NomorePass.request(url, function () {
            return JSON.stringify(params);
        }, { 'Content-Type': 'application/json' }, callback, fail);
    }

};

} else {
    console.log("Already loaded");
}
