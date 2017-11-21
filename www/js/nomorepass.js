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
    config: {},
    init: function (config) {
        if (typeof config == 'object') {
            NomorePass.config = config;
        }
        if (!('getidUrl' in NomorePass.config))
            NomorePass.config.getidUrl = "https://www.nomorepass.com/api/getid.php";
        if (!('checkUrl' in NomorePass.config))
            NomorePass.config.checkUrl = "https://www.nomorepass.com/api/check.php";
        if (!('authUrl' in NomorePass.config))
            NomorePass.config.authUrl = "https://www.nomorepass.com/api/auth.php";
        if (!('assocUrl' in NomorePass.config))
            NomorePass.config.assocUrl = "https://www.nomorepass.com/api/assoc.php";
        if (!('pingUrl' in NomorePass.config))
            NomorePass.config.pingUrl = "https://www.nomorepass.com/api/ping.php";
        if (!('referenceUrl' in NomorePass.config))
            NomorePass.config.referenceUrl = "https://www.nomorepass.com/api/reference.php";
        if (!('grantUrl' in NomorePass.config))
            NomorePass.config.grantUrl = "https://www.nomorepass.com/api/grant.php";
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
        for (var i = 0, n = charset.length; i < length; ++i) {
            retVal += charset.charAt(Math.floor(Math.random() * n));
        }
        return retVal;  
    },
    getQrText: function (site, callback) {
        // Protocolo 2 NMP
        // First, get Ticket
        NomorePass.post(NomorePass.config.getidUrl,{
            'site' : site
        }, function(data){
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
            NomorePass.stopped = false;
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
                            setTimeout(function() {NomorePass.check(callback);}, 3000);
                        }
                   }
               }
           } else {
               console.log ("Network Error");
           }
        });
    },
    stop: function () {
        NomorePass.stopped = true;
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
                    NomorePass.post(NomorePass.config.getidUrl,{
                        'site' : site
                   }, function(data){
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
    send: function (callback){
        var txt = "XXXXXXXXXXXX"+NomorePass.ticket;
        setTimeout(function(){NomorePass.ping(txt,callback);},4000);
    },
    ping: function (data,callback){
        if (NomorePass.stopped){
            NomorePass.stopped = false;
        }
        var ticket=data.substring(12);
        NomorePass.post(NomorePass.config.pingUrl,{'device': 'WEBDEVICE', 
        ticket:ticket},function(data){
            if ((data.resultado=='ok') && (data.ping=='ok')) {
              setTimeout(function(){NomorePass.ping("XXXXXXXXXXXX"+ticket,callback)},4000);
            } else {
               console.log(data);
               if (typeof callback == 'function') {
                callback(data);
               }
            }
          });
    },
    post : function (url,params,callback) {
        var formData = new FormData(); 
        for(var name in params) {
            formData.append(name,params[name]);
        }
        var xmlHttp = new XMLHttpRequest();
        xmlHttp.onreadystatechange = function()
        {
            if(xmlHttp.readyState == 4 && xmlHttp.status == 200)
            {
                callback(JSON.parse(xmlHttp.responseText));
            } 
        }
        xmlHttp.open("post", url); 
        xmlHttp.send(formData); 
    }
};
        
} else {
    console.log("Already loaded");
}  