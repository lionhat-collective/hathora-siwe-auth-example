import cors from 'cors';
import express from 'express';
import dotenv from 'dotenv'
import pkg from 'jsonwebtoken';
import { generateNonce, SiweMessage } from 'siwe';
const { sign, verify } = pkg;
dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

app.get('/nonce', function (_, res) {
    res.setHeader('Content-Type', 'text/plain');
    const nonce = generateNonce();
    const nonceToken = sign({ nonce }, process.env.HATHORA_APP_SECRET);
    return res.json({ nonce: nonce, nonceToken: nonceToken })
});

app.post('/verify', async function (req, res) {
    console.log('verify', req.body);
    const verifyTokenAsync = token => verify(token, process.env.HATHORA_APP_SECRET, (err, decoded) => new Promise((resolve, reject) => {
        if (err != null) return reject(err);
        resolve(decoded);
    }))
    const nonceToken = req.headers['x-nonce-token']
    if (!nonceToken) return res.status(400).json({ error: "Bad request" })
    const { nonce } = await verifyTokenAsync(nonceToken)
    try {
        let siweMessage = new SiweMessage(req.body.message);
        const fields = await siweMessage.validate(req?.body?.signature);
        if (fields.nonce !== nonce) {
            return res.status(400).json({ error: 'Invalid nonce' })
        }
        return res.json({ token: sign({ id: fields.address, publicAddress: fields.address, type: "siwe" }, process.env.HATHORA_APP_SECRET) })
    } catch(e) {
        console.log('error', e);
        res.status(400).json({ error: "Bad request." })
    }
});

app.listen(3001, () => console.log(`hathora siwe auth server listening on port: 3001`));