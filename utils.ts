import { pbkdf2, randomBytes } from "crypto";
import db from "./db";
import { promisify } from "util";
import { bytesToHex } from "@noble/hashes/utils";
import { argon2id } from "@noble/hashes/argon2";



export async function createUser(user: Omit<User, 'id'>): Promise<void> {
    const { hash, salt } = await generateSecureHash(user.password);
    // console.log({ ...user, password: hash, salt })
    const [newUser] = await db.create('users', { ...user, password: hash, salt });
    return newUser;
}



export async function generateHash(str: string) {
    const before = performance.now();
    const kdf = promisify(pbkdf2);

    const salt = randomBytes(64).toString('hex');
    const generatedSalt = performance.now();
    const derivedKey = await kdf(str, salt, 210_000, 64, 'sha512');
    const passwordHash = derivedKey.toString('hex');
    const after = performance.now();
    console.log(`generated salt: ${generatedSalt - before}ms`);
    console.log(`generated PBKDF2 hash: ${after - generatedSalt}ms`);

    return passwordHash;
}

async function generateSecureHash(str: string, salt?: string) {
    salt ??= bytesToHex(randomBytes(64));
    const before = performance.now();
    const hash = bytesToHex(argon2id(str, salt, { m: 2 ** 12, t: 2, p: 1, dkLen: 64 })); // FIXME: Bump this to 2**15 in prod
    // const hash = scrypt(str, salt, { N: 2 ** 17, r: 8, p: 1, dkLen: 32 });
    // const hash = await Bun.password.hash(str, { algorithm: "argon2id", memoryCost: 2 ** 15, timeCost: 2 });
    console.log(`generated Argon2id hash: ${performance.now() - before}ms`);
    return { hash, salt };
}


async function passwordMatchesHash(password: string, hash: string, salt: string) {
    const hashedPass = await generateSecureHash(password, salt);
    return hash == hashedPass.hash;
}

export async function findUser(email: string, password: string) {
    const [existingUser]: [DBUser] = await db.query('SELECT * FROM users WHERE email = $email', { email });
    // if (!existingUser) throw new Error("BAD_CREDENTAILS!");
    if (!existingUser) throw new Error("NOT_FOUND");
    const { salt, password: storedPassword } = existingUser;
    const validCredentials = await passwordMatchesHash(password, storedPassword, salt);
    if (!validCredentials) throw new Error("WRONG_PASSWORD"); //throw new Error("BAD_CREDENTAILS!");
    return existingUser;
}


async function test() {
    try {
        // await createUser({ name: "Hamid", role: "user", email: "hamid@gmail.com", password: "ham123" });
        // const hamid = await findUserByEmail("hamid@gmail.com");
        const before = performance.now();
        // const hash = await Bun.password.hash("hellothere");
        // const verified = await Bun.password.verify("hellothere", hash);
        // const newUser = await createUser({ name: "Abds", email: "gh.abds", role: "user", password: "AZERTY" });
        // const newUser = await findUser("gh.abds", "AZERTY");

        // console.log(newUser);
        const after = performance.now();
        console.log(`Created in: ${after - before}ms`);
        // const { hash, salt } = await generateSecureHash("ham123");
        // console.log({ hash, salt });
        // verifyPassword("ham124", hash, salt).then(console.log);
    } catch (error) {
        console.error(error);
    }
}

// await test()






export type User = { id?: string; name: string; email: string; password: string; role?: "user" | "admin", profilePic?: string };
export type DBUser = User & { id: string, password: string, salt: string; };