import * as jose from 'jose';

const secret = process.env.AUTH_SECRET || '06b9ce5826da4a206c10b2621279a40da43411476f2cb1cb2a3a7952d630fab2';

const secretKey = Buffer.from(secret, "hex");

export function verifyJWT(token: string) {
    return jose.jwtVerify(token, secretKey, { algorithms: ["HS256"] });
}


export function signJWT(payload: any) {
    return new jose.SignJWT(payload)
        .setProtectedHeader({ alg: "HS256" })
        .setIssuedAt()
        .setExpirationTime("1m")
        .sign(secretKey);
}


export function encryptJWT(payload: any) {
    return new jose.EncryptJWT(payload)
        .setProtectedHeader({ alg: "dir", enc: "A256GCM" })
        .setIssuedAt()
        .setExpirationTime("1m")
        .encrypt(secretKey);
}

export function decryptJWT(jwt: string) {
    return jose.jwtDecrypt(jwt, secretKey, { contentEncryptionAlgorithms: ["A256GCM"], keyManagementAlgorithms: ["dir"], });
}



(async function main() {
    const payload = { hello: "world", marco: "Polo", user: "Jamal" };
    // const signedHello = await sign(payload);
    // console.log(signedHello)
    // const verifiedHello = await verify(signedHello, { algorithms: ["HS256"] });
    // console.log(verifiedHello.payload)

    const encryptedPayload = `eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..vquX9c4-FHAbk3Rl.UKXgCcD45hKQBzuwK0lcouT-wAFypiK7C5Imme2Wjn8byngWk7mm6yJ7qCbbeQkQRwo91Uzzl1AU4TN2y5w2dsb3Bmi0iJwR4K5lEFv4RI5EPb8lcAc_Gral8HEfuuS7yDWaud3eAqnXoHb904CSZQ8.NoVgJTd-uSgN2DaWB2gnsQ`;
    // const encryptedPayload = await encryptJWT(payload);
    // console.log(encryptedPayload);

    const decryptedPayload = await decryptJWT(encryptedPayload);
    console.log(decryptedPayload.payload.exp);
});
