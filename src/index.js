import cors from 'cors';
import express from 'express';
import dotenv from 'dotenv'
import { sign } from 'jsonwebtoken'
import { generateNonce, SiweMessage } from 'siwe';
dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

app.get('/nonce', function (_, res) {
    res.setHeader('Content-Type', 'text/plain');
    res.send(generateNonce());
});

app.post('/verify', async function (req, res) {
    const { message, signature } = req.body;
    const siweMessage = new SiweMessage(message);
    try {
        const fields = await siweMessage.validate(signature);
        return res.json({ token: sign({ id: fields.address, publicAddress: fields.address }, process.env.HATHORA_APP_SECRET) })
    } catch {
        res.status(400).json({ error: "Bad request." })
    }
});

app.listen(3000, () => console.log(`hathora siwe auth server listening on port: 3000`));