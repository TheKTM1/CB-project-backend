import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';

const cipherKey = 'keyword123456789';

export function aes_decrypt(encryptedText: string){
    const iv = encryptedText.slice(0, 24);
    const encrypted = encryptedText.slice(24);
    const decipher = createDecipheriv('aes-128-gcm', cipherKey, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');

    return decrypted;
}

export function aes_encrypt(textToEncrypt: string){
    const iv = randomBytes(12).toString('hex');
    const cipher = createCipheriv('aes-128-gcm', cipherKey, iv);
    let encrypted = cipher.update(textToEncrypt, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    encrypted = iv + encrypted;

    return encrypted;
}