import cors from 'cors';
import express from 'express';
import dotenv from 'dotenv'
import pkg from 'jsonwebtoken';
import { generateNonce, SiweMessage } from 'siwe';
const { sign } = pkg;
dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

app.get('/nonce', function (_, res) {
    res.setHeader('Content-Type', 'text/plain');
    const nonce = generateNonce();
    const nonceToken = sign({ nonce }, process.env.HATHORA_APP_SECRET);
    res.send({nonce, nonceToken});
});

app.post('/verify', async function (req, res) {
    //log something
    console.log('verify', req.body);
    const { message, signature } = req.body;
    let siweMessage;
    try {
        siweMessage = new SiweMessage(message);
    } catch(e) {
        console.log('error', e);
        res.status(500).json({ error: "Bad request." })
    }
    console.log('siweMessage', siweMessage);
    try {
        const fields = await siweMessage.validate(signature);
        console.log('fields', fields);
        return res.json({ token: sign({ id: fields.address, publicAddress: fields.address }, process.env.HATHORA_APP_SECRET) })
    } catch(e) {
        console.log('error', e);
        res.status(400).json({ error: e })
    }
});

app.listen(3001, () => console.log(`hathora siwe auth server listening on port: 3001`));