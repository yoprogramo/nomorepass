/*
 * nomorepass.js
 * 
 * Library to access nomorepass.com security services
 * 
 * (C) 2018-2021 Jose Antonio Espinosa (yoprogramo@gmail.com) 
 * https://momorepass.com
 * 
 */
var CryptoJS = require('crypto-js');
const FormData = require ('form-data');
const axios = require('axios');
const { randomInt } = require('crypto');

const REQUEST_TIMEOUT = 15000;
const MAX_BODY_SIZE = 1024 * 1024;
const activeRequests = new Set();
const pollingTimers = new Set();

function schedulePoll(callback, delay) {
    const timer = setTimeout(function () {
        pollingTimers.delete(timer);
        callback();
    }, delay);
    pollingTimers.add(timer);
}

function cancelPending() {
    for (const controller of activeRequests) controller.abort();
    activeRequests.clear();
    for (const timer of pollingTimers) clearTimeout(timer);
    pollingTimers.clear();
}

function post(url, data, headers, callback) {
    const controller = new AbortController();
    activeRequests.add(controller);
    // Absolute deadline also covers connection establishment and redirects.
    const timer = setTimeout(function () { controller.abort(); }, REQUEST_TIMEOUT);
    return axios.post(url, data, {
        headers: headers,
        timeout: REQUEST_TIMEOUT,
        maxContentLength: MAX_BODY_SIZE,
        maxBodyLength: MAX_BODY_SIZE,
        maxRedirects: 3,
        signal: controller.signal
    }).then(function (response) {
        if (!controller.signal.aborted) callback(response.data);
    }, function (error) {
        // Explicit stop/init cancellation does not deliver stale callbacks.
        if (!controller.signal.aborted || activeRequests.has(controller)) {
            callback({ resultado: 'error', error: error.code || 'REQUEST_FAILED' });
        }
    }).finally(function () {
        clearTimeout(timer);
        activeRequests.delete(controller);
    });
}



var NoMorePass = {};

function nmp_newtoken () {
    var length = 12,
    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    retVal = "";
    for (var i = 0, n = charset.length; i < length; ++i) {
        retVal += charset.charAt(randomInt(n));
    }
    return retVal;  
}

function nmp_post (url,params,callback) {
    const formData = new FormData();
    for(var name in params) {
        formData.append(name,params[name]);
    }
    let theaders = formData.getHeaders();
    theaders.apikey = NoMorePass.apikey;
    return post(url, formData, theaders, callback);
}

function iot_post (url,params,callback) {
    return post(url, params, {"Content-Type": "application/json"}, callback);
}

function nmp_decrypt (password,token){
    var pass = CryptoJS.AES.decrypt(password, token).toString(CryptoJS.enc.Utf8);
    return pass;
}

function nmp_check(callback) {
    if (NoMorePass.stopped){
        return; // Execution stopped, not calling callback
    }
    nmp_post(NoMorePass.checkUrl,{
        'ticket': NoMorePass.ticket
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
                       password: nmp_decrypt(data.password,NoMorePass.token),
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
                        schedulePoll(function() {nmp_check(callback);}, 3000);
                    }
               }
           }
       } else {
           if (typeof callback == 'function') callback(true, data.error || 'request_failed');
       }
    });
}

function nmp_ping(data,callback){
    if (NoMorePass.stopped) return;
    var ticket=data.substring(12);
    nmp_post(NoMorePass.pingUrl,{'device': 'WEBDEVICE', 
    ticket:ticket},function(data){
        if ((data.resultado=='ok') && (data.ping=='ok')) {
          schedulePoll(function(){nmp_ping("XXXXXXXXXXXX"+ticket,callback)},4000);
        } else {
           if (typeof callback == 'function') {
            callback(data);
           }
        }
      });
}

exports.init = function (config) {
    cancelPending();
    if (typeof config == 'object') {
        NoMorePass = config;
    }
    if (!('getidUrl' in NoMorePass))
        NoMorePass.getidUrl = "https://api.nomorepass.com/api/getid.php";
    if (!('checkUrl' in NoMorePass))
        NoMorePass.checkUrl = "https://api.nomorepass.com/api/check.php";
    if (!('authUrl' in NoMorePass))
        NoMorePass.authUrl = "https://api.nomorepass.com/api/auth.php";
    if (!('assocUrl' in NoMorePass))
        NoMorePass.assocUrl = "https://api.nomorepass.com/api/assoc.php";
    if (!('pingUrl' in NoMorePass))
        NoMorePass.pingUrl = "https://api.nomorepass.com/api/ping.php";
    if (!('referenceUrl' in NoMorePass))
        NoMorePass.referenceUrl = "https://api.nomorepass.com/api/reference.php";
    if (!('grantUrl' in NoMorePass))
        NoMorePass.grantUrl = "https://api.nomorepass.com/api/grant.php";
    if (!('apikey' in NoMorePass))
        NoMorePass.apikey='FREEAPIKEY';
    NoMorePass.stopped = false;
    NoMorePass.expiry = null;
}

exports.getQrText  = function (site, callback) {
    // Protocolo 2 NMP
    // First, get Ticket
    let params = {
        "site": site
    };
    if (NoMorePass.expiry!=null) {
        params['expiry'] = NoMorePass.expiry;
    }
    nmp_post(NoMorePass.getidUrl,params,
    function(data){
      if (data.resultado=='ok') {
          var tk = nmp_newtoken();
          NoMorePass.token = tk;
          NoMorePass.ticket = data.ticket;
          var text = 'nomorepass://'+tk+data.ticket+site;
          if (typeof callback == 'function') {
            callback(text);
          }
      } else {
          callback(false);
      }
   });
}

exports.start = function (callback) {
    // Protocolo 2 NMP
    // Using ticket only
    nmp_check(callback);
}

exports.stop = function () {
    NoMorePass.stopped = true;
    cancelPending();
}

exports.getQrSend = function (site, user, pass, extra, callback) {
    // Protocol 2 reverse
    // First we made grant then ping
    if (site==null) {
        // site is the id device of origin, if null use generic WEBDEVICE
        site = "WEBDEVICE";
    }
    var device = site;
    nmp_post(NoMorePass.referenceUrl,
        { 'device': device, 
          'fromdevice': device},
        function(response){
            if (response.resultado=='ok') {
                var tokenfb = response.token;
                let params = {
                    "site": site
                };
                if (NoMorePass.expiry!=null) {
                    params['expiry'] = NoMorePass.expiry;
                }
                nmp_post(NoMorePass.getidUrl,params,
                     function(data){
                  if (data.resultado=='ok') {
                    var tk = nmp_newtoken();
                    NoMorePass.token = tk;
                    NoMorePass.ticket = data.ticket;
                    var ep = CryptoJS.AES.encrypt(pass, tk);
                    // Make the grant and return text
                    if (typeof extra == 'object') {
                        extra = JSON.stringify(extra);
                    }
                    nmp_post(NoMorePass.grantUrl,{
                        'grant': 'grant',
                        'ticket': NoMorePass.ticket,
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
}

exports.getQrNomoreKeys = function (site, user, pass, type, extra, callback) {
    // Protocol 2 reverse
    // First we made grant then ping
    // for nomorekeys phisical keys (soundkey or lightkey)
    if (type!='SOUNDKEY' && type!='LIGHTKEY' && type!='BLEKEY')
        type="KEY";
    if (site==null) {
        // site is the id device of origin, if null use generic WEBDEVICE
        site = "WEBDEVICE";
    }
    var device = site;
    nmp_post(NoMorePass.referenceUrl,
        { 'device': device, 
          'fromdevice': device},
        function(response){
            if (response.resultado=='ok') {
                var tokenfb = response.token;
                let params = {
                    "site": site
                };
                if (NoMorePass.expiry!=null) {
                    params['expiry'] = NoMorePass.expiry;
                }
                nmp_post(NoMorePass.getidUrl,params,
                 function(data){
                  if (data.resultado=='ok') {
                    var tk = nmp_newtoken();
                    NoMorePass.token = tk;
                    NoMorePass.ticket = data.ticket;
                    if (type=='SOUNDKEY'){
                        pass = pass.substr(0,14).padEnd(14," ");
                    } else 
                        if (type=='LIGHTKEY'){
                            pass=""+parseInt(pass)%65536;
                        }
                    var ep = CryptoJS.AES.encrypt(pass, tk);
                    // Make the grant and return text
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
                    nmp_post(NoMorePass.grantUrl,{
                        'grant': 'grant',
                        'ticket': NoMorePass.ticket,
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
}

exports.send = function (callback){
    var txt = "XXXXXXXXXXXX"+NoMorePass.ticket;
    schedulePoll(function(){nmp_ping(txt,callback);},4000);
}

exports.setExpiry = function (expiry) {
    NoMorePass.expiry = expiry;
}

exports.sendRemotePassToDevice = function (cloud,deviceid,secret,username,password,callback) {
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
    if (NoMorePass.expiry!=null) {
        params['expiry'] = NoMorePass.expiry;
    }
    nmp_post(NoMorePass.getidUrl, params,
     function(data){
        if (data.resultado=='ok') {
            let ticket = data.ticket;
            let ep = CryptoJS.AES.encrypt(password, token);
            nmp_post(NoMorePass.grantUrl, {
                'grant': 'grant', 
                'ticket': ticket, 
                'user': username, 
                'password' : ''+ep, 
                'extra': JSON.stringify({'type': 'remote'})
            }, function (data){
                if (data.resultado=='ok') {
                    iot_post (cloud,
                        {'hash': token.substring(0,10), 
                        'deviceid': deviceid, 
                        'ticket': ticket},
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
}