/*
 * nomorepass.js
 * 
 * Library to access nomorepass.com security services
 * 
 * (C) 2017 Jose Antonio Espinosa (yoprogramo@gmail.com) 
 * https://momorepass.com
 * 
 */
var CryptoJS = require("crypto-js");
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
    /*var formData = new FormData(); 
    for(var name in params) {
        formData.append(name,params[name]);
    }
    console.log(formData);*/
    request.post({url: url, form: params}, 
        function (err, httpResponse, body) {
            if (err) {
                return console.error('call failed:', err);
            }
            //console.log(body);
            callback(JSON.parse(body));
            //console.log('Upload successful!  Server responded with:', body);
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
          callback(text);
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
