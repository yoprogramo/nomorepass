# nomorepass
Libraries to use nomorepass.com security services

nomorepass is a library to use nomorepass in Node. It is intended to use in any environment, so it does not generate / print the qr-code needed, instead provides the text that should be included in the qrcode (you can generate using any qrcode libraries).

## Installation

```
npm install nomorepass
```

## Usage

```js
 var nmp = require('nomorepass');
// Initialize the environment (do it each time you need)
 nmp.init();
 // Launch the process for testsite (replace with you app-id)
 nmp.getQrText('testsite', function(text){
    if (text==false) {
        console.log("Error calling nomorepass");
    } else {
        console.log(text);
        // Show the qr generated for text
        // Start waiting for mobile app scanning 
        nmp.start(function(error,data){
            if (error) {
                console.log("Error "+data);
            } else {
                console.log(data);
                // Use the data provided:
                // {user: 'username', password: 'password', extra: json-encoded-extra-info}
            }
         });
        // Stop after 1 minute (you can stop manually calling nmp.stop())
        setTimeout(nmp.stop,60000);
    }
 });
```
## Help / more info

Visit [nomorepass.com](https://nomorepass.com) or leave a Issue

(C) 2017 Nomorepass.com