import { Surreal } from "surrealdb.node"

const db = new Surreal();

await db.connect('ws://127.0.0.1:8000')
    .then(() => console.log('Connected to DB'))
    .then(() => db.signin({ username: 'root', password: 'root' }))
    .then(() => db.use({ ns: 'test', db: 'new_auth' }))
    .catch(err => {
        console.error('DB_CONNECTION_FAILED\n', err);
        throw new Error("Database connection failed");
        // setTimeout(() => {}, 3000);
    });

let created = await db.select("users:⟨2⟩");

// console.log(created);

export default db;