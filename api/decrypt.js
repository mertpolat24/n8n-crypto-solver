const crypto = require('crypto');

const PRIVATE_KEY_PEM = process.env.RSA_PRIVATE_KEY;

module.exports = (req, res) => {
    if (req.method !== 'POST') {
        return res.status(405).send('Method Not Allowed');
    }

    try {
        const { encrypted_aes_key } = req.body;

        if (!encrypted_aes_key) {
            return res.status(400).json({ error: 'Missing encrypted_aes_key in body' });
        }
        
        if (!PRIVATE_KEY_PEM) {
             return res.status(500).json({ error: 'RSA_PRIVATE_KEY is not configured on the server.' });
        }

        const privateKeyObject = crypto.createPrivateKey(PRIVATE_KEY_PEM);
        
        const rawSymmetricKeyBuffer = crypto.privateDecrypt( // 'raw' olarak yeniden adlandırıldı
            {
                key: privateKeyObject, 
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256', 
            },
            Buffer.from(encrypted_aes_key, 'base64')
        );

        // KRİTİK DÜZELTME: Anahtarın sadece ilk 16 baytını al (128 bit için)
        let symmetricKeyBuffer;
        if (rawSymmetricKeyBuffer.length !== 16) {
             // 18 bayt gelme durumunda ilk 16 baytı alır (Temizler)
             symmetricKeyBuffer = rawSymmetricKeyBuffer.subarray(0, 16); 
             // Konsola uyarı log'u ekleyebilirsiniz: console.log(`Anahtar boyutu düzeltildi: ${rawSymmetricKeyBuffer.length} -> ${symmetricKeyBuffer.length}`);
        } else {
             symmetricKeyBuffer = rawSymmetricKeyBuffer;
        }

        const decryptedKeyBase64 = symmetricKeyBuffer.toString('base64'); // Şimdi temizlenmiş 16 baytlık anahtarı Base64'e çeviriyoruz.

        res.status(200).json({
            decrypted_aes_key: decryptedKeyBase64,
            status: "SUCCESS_EXTERNAL_DECRYPT"
        });

    } catch (e) {
        res.status(421).json({
            error: 'DECRYPT_FAILURE_EXTERNAL',
            message: e.message,
            hint: 'The OpenSSL library on the server failed to decrypt the key (OAEP padding issue likely).'
        });
    }
};
