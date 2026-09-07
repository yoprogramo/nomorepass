# nomorepass
Libraries to use nomorepass.com security services

nomorepass is a library to use nomorepass in Node or browser. It is intended to use in any environment, so it does not generate / print the qr-code needed, instead provides the text that should be included in the qrcode (you can generate using any qrcode libraries).

## Node Installation

```
npm install nomorepass
```

## Usage

To receive passwords:

```js
 var nmp = require('nomorepass');
// Initialize the environment (do it each time you need)
 nmp.init({'apikey':'MYAPIKEY'});
 // Launch the process for testsite (replace with you app-id)
 const stopTimer = setTimeout(nmp.stop, 60000);
 nmp.getQrText('testsite', function(text){
    if (text==false) {
        clearTimeout(stopTimer);
        console.log("Error calling nomorepass");
    } else {
        console.log(text);
        // Show the qr generated for text
        // Start waiting for mobile app scanning 
        nmp.start(function(error,data){
            clearTimeout(stopTimer);
            if (error) {
                console.log("Error "+data);
            } else {
                console.log(data);
                // Use the data provided:
                // {user: 'username', password: 'password', extra: json-encoded-extra-info}
            }
         });

    }
 });
```

To send passwords:

```js
var nmp = require('nomorepass');
// Initialize the environment (do it each time you need)
nmp.init({'apikey':'MYAPIKEY'});
var user = 'usernametosend';
var pass = 'thepasstosend';
nmp.getQrSend (null,user,pass,{type:'pwd'}, 
    function (text){
        if (text==false){
            console.log("Error calling nmp");
        } else {
            console.log(text);
            // Show the qr with this text
            // wait to be scanned and received
            // by the app
            nmp.send (function(data){
                console.log(data);
                // hide qr here.
            })
        }
    }
);
```
## Node request limits and cancellation

The Node implementation requires Node.js 16 or later (native `AbortController`).

All HTTP requests, including the initial ticket request, have a 15-second timeout
and cancellation deadline, a 1 MiB response/request body limit, and at most three
redirects. Transport failures use the existing failure callbacks (`false` for QR
creation; `(true, errorCode)` while receiving credentials).

`stop()` aborts in-flight requests and clears pending polling timers without
calling their callbacks. Call `init()` before starting a new session; it also
cancels work from the previous session. Install any overall application deadline
before calling `getQrText()`, as shown above.

Tokens use Node's cryptographic random generator (Web Crypto in the browser).
Protocol 2 requires 12 base62 characters, providing approximately 71 bits of
entropy. Increasing that entropy requires a coordinated protocol/client change.
The browser implementation requires Web Crypto and has no insecure fallback.

## In the browser

Browser requests use Fetch with streamed response reading, a 15-second deadline
(including the initial ticket request and response download), and a 1 MiB limit
on the serialized request and decoded response bytes. Redirects are rejected;
configure the final endpoint URL directly. Modern browsers with Fetch, response
streams, `Response.blob()`, `TextDecoder`, `AbortController`, and Web Crypto are required.

`stop()` and `init()` abort active requests and clear polling timers without
calling cancelled callbacks. Call `init()` before starting another session after
`stop()`. HTTP errors, network failures, invalid JSON, oversized payloads, and
timeouts are reported through existing failure callbacks. `postJson()` uses its
optional failure callback, or its normal callback if none is provided.


There are included libraries to use directly on the browser. You'll find inside the www directory. To use inside your page you should include this files:

```html
<script src="js/aes.js"></script>
<script src="js/nomorepass.js"></script>
```

We have included for demo purpouses the QRCode for Javascript library from http://jeromeetienne.github.com/jquery-qrcode/

```html
<script src="js/qrcode.js"></script>
```

Designate a div where show the qr (#qrcode in the example).

To receive a password (using QRCode to show the qr) and fill two fields (#username and #password):

```js
var qrelement = document.querySelector('#qrcode');
NomorePass.init({'apikey':'MYAPIKEY'});
NomorePass.getQrText(window.location.href,function(text){
    qrelement.innerHTML="";
    qrelement.style.display="block";
    new QRCode(qrelement, text);
    qrelement.onclick=function(e){
        window.open(text,'_system');
    };
    // Waiting...
    NomorePass.start(function(error,data){
        if (error)
            alert (data);
        else {
            document.querySelector('#username').value=data.user;
            document.querySelector('#password').value=data.password;
            qrelement.innerHTML="";
        }
    });
});
```

To send user and pass to the phone:

```js
var qrelement = document.querySelector('#qrcode');
NomorePass.init({'apikey':'MYAPIKEY'});
NomorePass.getQrSend ('testpage',user,pass,{type:'pwd'}, 
    function (text){
        if (text==false){
            alert("Error calling nmp");
        } else {
            // Show the qr with this text
            qrelement.innerHTML="";
            qrelement.style.display="block";
            new QRCode(qrelement, text);
            qrelement.onclick=function(e){
                window.open(text,'_system');
            };
            // wait to be scanned and received
            // by the app (optional)
            NomorePass.send (function(data){
                qrelement.innerHTML="<p>Password received</p>";
                console.log(data);
                // hide qr here.
            })
        }
    }
);
```

### test

You can test the browser libraries by opening www/test.html in your favourite browser and receive / send passwords.


## How to use NoMorePass

1. Download and install the mobile app

* [android] https://play.google.com/store/apps/details?id=com.biblioeteca.apps.NoMorePass
* [ios] https://itunes.apple.com/us/app/no-more-pass/id1199780162?l=es&ls=1&mt=8

3. Open it and create a new password (or use some of yours)
4. Then you can scan the qrcode generated by the library to send securely this password to your app or send/update passwords from your code to the app.

## Help / more info

Visit [nomorepass.com](https://nomorepass.com) or leave an Issue

(C) 2021 Nomorepass.com
