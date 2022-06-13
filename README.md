# veramo-bls-issuer
Veramo issuer implementation for BBS+ signatures

# How to run this demo

1. The firs thing you will need is a valid domain for the did:web. You can start the web server under did-web-server, and use ngrok to make it to a public address. The web server will run but it won't provide any valid DID yet as the public key was not created yet.
2. Take note of the ngrok public domain for the https url.
3. Go to src/create-identiifer and update the alias to match the domain from #2
4. Run the create-identifier script. That will create a new key pair in Veramo. Take note of the publicKeyHex representation.
5. Go back to the did-web-server. Change the public key in the routes/index.js file to use the new key created in #4. The web server is using nodemon so there is no need to restart it.
6. Go to src/issue-vc and update the did and public key. You can run that script and get a new VC issued.
