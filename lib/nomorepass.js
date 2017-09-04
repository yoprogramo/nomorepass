/*
 * nomorepass.js
 * 
 * Library to access nomorepass.com security services
 * 
 * (C) 2017 Jose Antonio Espinosa (yoprogramo@gmail.com) 
 * https://momorepass.com
 * 
 */
var CryptoJS = require('crypto-js');
var request = require('request');


var NoMorePass = {};

function nmp_newtoken () {
    var length = 12,
    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    retVal = "";
    for (var i = 0, n = charset.length; i < length; ++i) {
        retVal += charset.charAt(Math.floor(Math.random() * n));
    }
    return retVal;  
}

function nmp_post (url,params,callback) {
    request.post({url: url, form: params}, 
        function (err, httpResponse, body) {
            if (err) {
                return console.error('call failed:', err);
            }
            callback(JSON.parse(body));
        });
}

function nmp_decrypt (password,token){
    var pass = CryptoJS.AES.decrypt(password, token).toString(CryptoJS.enc.Latin1);
    return pass;
}

function nmp_check(callback) {
    if (NoMorePass.stopped){
        NoMorePass.stopped = false;
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
                        setTimeout(function() {nmp_check(callback);}, 3000);
                    }
               }
           }
       } else {
           alert ("Error en la llamada auth");
       }
    });
}

function nmp_ping(data,callback){
    var ticket=data.substring(12);
    nmp_post(NoMorePass.pingUrl,{'device': 'WEBDEVICE', 
    ticket:ticket},function(data){
        if ((data.resultado=='ok') && (data.ping=='ok')) {
          setTimeout(function(){nmp_ping("XXXXXXXXXXXX"+ticket)},4000);
        } else {
           console.log(data);
           if (typeof callback == 'function') {
            callback(data);
           }
        }
      });
}

exports.init = function (config) {
    if (typeof config == 'object') {
        NoMorePass = config;
    }
    if (!('getidUrl' in NoMorePass))
        NoMorePass.getidUrl = "https://www.nomorepass.com/api/getid.php";
    if (!('checkUrl' in NoMorePass))
        NoMorePass.checkUrl = "https://www.nomorepass.com/api/check.php";
    if (!('authUrl' in NoMorePass))
        NoMorePass.authUrl = "https://www.nomorepass.com/api/auth.php";
    if (!('assocUrl' in NoMorePass))
        NoMorePass.assocUrl = "https://www.nomorepass.com/api/assoc.php";
    if (!('pingUrl' in NoMorePass))
        NoMorePass.pingUrl = "https://www.nomorepass.com/api/ping.php";
    if (!('referenceUrl' in NoMorePass))
        NoMorePass.referenceUrl = "https://www.nomorepass.com/api/reference.php";
    if (!('grantUrl' in NoMorePass))
        NoMorePass.grantUrl = "https://www.nomorepass.com/api/grant.php";
    NoMorePass.stopped = false;
}

exports.getQrText  = function (site, callback) {
    // Protocolo 2 NMP
    // First, get Ticket
    nmp_post(NoMorePass.getidUrl,{
        'site' : site
   }, function(data){
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
                nmp_post(NoMorePass.getidUrl,{
                    'site' : site
               }, function(data){
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

exports.send = function (callback){
    var txt = "XXXXXXXXXXXX"+NoMorePass.ticket;
    setTimeout(function(){nmp_ping(txt,callback);},4000);
}