const express = require('express');
const crypto = require('node:crypto');
const { 
    generateRegistrationOptions, 
    verifyRegistrationResponse, 
    generateAuthenticationOptions, 
    verifyAuthenticationResponse
} = require('@simplewebauthn/server');

const { isoUint8Array } = require('@simplewebauthn/server/helpers');

if(!globalThis.crypto) {
    globalThis.crypto = crypto;
}

const PORT = 3000;
const app = express();

// using middlewares
app.use(express.static('./public'));        // public directory for client code
app.use(express.json());

// states
const userStore = {};
const challengeStore = {};


app.post('/register', (req, res) => {
    const { username, password } = req.body;
    const id = `user_${Date.now()}`;

    const user = {
        id, 
        username, 
        password
    }

    // check if username not already taken
    userStore[id] = user;
    console.log('register successful', userStore[id]);

    return res.json({ id });
})

app.post('/register-challenge', async (req, res) => {
    const { userId } = req.body;

    if (!userStore[userId])
        return res.status(404).json({ msg: "user not found!" });

    const user = userStore[userId];

    // make a challenge for user
    const challengePayload = await generateRegistrationOptions({
        rpID: 'localhost',              // means frontend on which domain
        rpName: 'Localhost Machine',
        userID: isoUint8Array.fromUTF8String(user.id),          // have to convert userId from stirng, coz: Error: String values for `userID` are no longer supported, answer: https://simplewebauthn.dev/docs/advanced/server/custom-user-ids
        userName: user.username,
        userDisplayName: user.username, // You can use a more friendly display name if available
    });

    // console.log('Generated registration options:', challengePayload);

    // user will use this particular challenge to sign that particular thing on frontEnd
    challengeStore[userId] = challengePayload.challenge;
    return res.json({ options: challengePayload });
});

app.post('/register-verify', async(req, res) => {
    const { userId, cred } = req.body;
    
    if (!userStore[userId])
        return res.status(404).json({ msg: "user not found!" });

    const user = userStore[userId];
    const challenge = challengeStore[userId];
    
    const verificationResult = await verifyRegistrationResponse({
        expectedChallenge: challenge,
        expectedOrigin: "http://localhost:3000",
        expectedRPID: "localhost",
        response: cred 
    });

    if(!verificationResult.verified)
        return res.json({ error: "could not verify!" });
    
    userStore[userId].passkey = verificationResult.registrationInfo;

    return res.json({ verified: true });
})

app.post('/login-challenge', async(req, res) => {
    const { userId } = req.body;
    if (!userStore[userId])
        return res.status(404).json({ msg: "user not found!" });

    const  opts = await generateAuthenticationOptions({
        rpID: 'localhost',
    });

    // save this challenge 
    challengeStore[userId] = opts.challenge;

    return res.json({ options: opts });  
})

app.post('/login-verify', async(req, res) => {
    const { userId, cred } = req.body;
    if (!userStore[userId])
        return res.status(404).json({ msg: "user not found!" });

    const user = userStore[userId];

    const challenge = challengeStore[userId];
    const result = await verifyAuthenticationResponse({
        expectedChallenge: challenge,
        expectedOrigin: "http://localhost:3000",
        expectedRPID: 'localhost',
        response: cred,
        authenticator: user.passkey
    });

    if(!result.verified) 
        return res.json({ error: "something went wrong!" });

    // login the user: (session, cookies, jwt)
    return res.json({ success: true, userId });
})

app.listen(PORT, () => console.log(`server is listening at port ${PORT}`));