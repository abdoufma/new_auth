import express from "express";
import type { Request, Response, NextFunction } from "express";
import cors from "cors";
import cookieParser from 'cookie-parser';
import hbs from "express-handlebars";

import { decryptJWT, encryptJWT } from "./test";
import { JWEDecryptionFailed, JWEInvalid } from "jose/errors";
import { createUser, findUser, type User } from "./utils";
const app = express();
const port = +(process.env.PORT || 8080);

const isProd = process.env.NODE_ENV === "production";
const DOMAIN = isProd ? 'appifire.io' : 'localhost';
const frontendURL = process.env.NEXT_PUBLIC_FRONTEND_URL;
const prodOrigins = [`https://auth.appifire.io`, `https://next.appifire.io`];
const devOrigins = [`http://localhost`, `http://localhost:8080`, `http://localhost:3000`];
const allowedOrigins = isProd ? prodOrigins : devOrigins;

app.engine('html', hbs.engine({ defaultLayout: "" }));
app.set('view engine', 'html');
app.set('views', './public');

app.use(cors({ credentials: true, origin: allowedOrigins }));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(cookieParser());

const sessionMaxAge = 60; // 60 seconds

app.get("/", (req, res) => res.render("index", { text: true, 'lastName': 'hello' }));

app.get('/login', (_, res) => res.render('login'));


app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  console.count('login attempt');
  try {
    const foundUser = await findUser(email, password);
    console.log({ foundUser });
    const token = await encryptJWT(foundUser);
    console.log(`user ${foundUser.email} just logged in.`);
    res.cookie('jwt', token, { httpOnly: true, signed: false, maxAge: sessionMaxAge * 1000, secure: isProd, sameSite: "lax", domain: isProd ? DOMAIN : undefined });
    // res.status(200).json({ success: true });
    res.render('dashboard', foundUser);
  } catch (err: any) {
    switch (err.message) {
      case 'NOT_FOUND':
        res.status(404).send({ success: false, error: "User not found" }); break;
      case 'WRONG_PASSWORD':
        res.status(401).send({ success: false, error: "Wrong password, bro!" }); break;

      default:
        res.status(401).send({ success: false, error: err.message ?? "Bad request" }); break;
    }

  }
});


app.post('/authorize', async (req, res) => {
  try {
    const { email, password } = req.body;
    const foundUser = await findUser(email, password);
    if (!foundUser) return res.status(400).json({ success: false, error: "Bad credentials" });
    // ? We don't need to send the token here, we can let next auth generate and encrypt the token for us, we only need to be able to read those tokens
    res.json({ success: true, user: foundUser });
  } catch (error: unknown) {
    console.error(`[SERVER AUTH ERROR]: ${error}`);
    res.status(500).send({ success: false, error: "Authentication error: " + (error as Error).message });
  }
});

app.post('/signup', async (req, res) => {
  console.log('Signup attempt...')
  // return res.send({ success: false, error: "you fucked up, son" });
  try {
    const { name, role, email, password } = req.body;
    const newUser = createUser({ name, email, password, role });
    res.json({ success: true, user: newUser });
  } catch (error: unknown) {
    console.error(`[SERVER AUTH ERROR]: ${error}`);
    res.status(500).send({ success: false, error: "Authentication error: " + (error as Error).message });
  }
});


app.get('/dashboard', async (req, res) => {
  console.log("/dashboard");
  try {

    const token = req.cookies.jwt;
    const decoded = await decryptJWT(token)
    const user = (decoded.payload as User);
    if (!user) {
      res.status(401).send("Invalid Credentials");
    } else {
      console.log(user);
      res.render('dashboard', { ...user, frontendURL });
    }
  } catch (error: any) {
    console.error(error.message);
    if (error instanceof Error) {
      if (error instanceof JWEInvalid) return res.status(400).send(`<h2>Session token invalid (Error code: ${error.code})</h2>`);
      if (error instanceof JWEDecryptionFailed) return res.status(400).send(`<h2>Error reading session token (Error code: ${error.code})</h2>`);
    }

    res.send(401).send(`<h2>${(error as any).message ?? "Unexpected Auth Error"}</h2>`);
  }
});

app.all('/logout', async (req, res) => {
  console.log('logging out...');
  res.clearCookie('jwt');
  res.redirect('/login');
  res.end();
})

app.all('/api/test', (req, res) => {
  // res.cookie('jwt', 'yep', { domain: DOMAIN }).status(200).end('done');
  const token = req.cookies.jwt;
  console.log({ foundCookie: token });
  // const decodedCookie = cookieParser.signedCookie(token, secret)
  // console.log({ decodedCookie });
  res.end("ok");
});

app.all('/admin/protected', authenticateAdmin, async (req, res) => {
  console.log(`${req.method} /admin/protected`);

  const token = req.cookies.jwt;
  if (!token) res.status(401).send("<h3>Session cookie does not exist or has expired</h3>");
  const decoded = await decryptJWT(token);
  const timeUntilExpiration = decoded.payload.exp! - (Date.now() / 1000);
  res.send(`<h2>This is a protected *admin* resource (time left : ${timeUntilExpiration})</h2>`);
});

app.all('/user/protected', authenticateUser, async (req, res) => {
  console.log(`${req.method} /user/protected`);
  res.send('<h2>This is a protected *User* resource</h2>')
});


async function authenticateUser(req: Request, res: Response, next: NextFunction) {
  try {
    const token = req.cookies.jwt;
    if (!token) res.status(401).send("<h3>Session cookie does not exist or has expired</h3>");
    const decoded = await decryptJWT(token);
    console.log(decoded.payload)
    const timeUntilExpiration = decoded.payload.exp! - (Date.now() / 1000);
    console.log(`Token expires in ${timeUntilExpiration}s`);
    if (timeUntilExpiration < 0) res.send('<h3>Token expired!</h3>')
    if (decoded.payload) {
      next();
    } else {
      res.status(403).send("You are not authorized to access this resource");
    }
  } catch (error: any) {
    res.status(401).send(`<h2>Auth Error: ${error.message}</h2>`);
  }

};

async function authenticateAdmin(req: Request, res: Response, next: NextFunction) {
  try {
    const token = req.cookies.jwt;
    if (!token) res.status(401).send("<h3>Session cookie does not exist or has expired</h3>");
    const decoded = await decryptJWT(token);
    console.log(decoded.payload)
    const timeUntilExpiration = decoded.payload.exp! - (Date.now() / 1000);
    console.log(`Token expires in ${timeUntilExpiration}s`);
    if (timeUntilExpiration < 0) res.send('<h3>Token expired!</h3>')
    const user = decoded.payload as User;
    if (user && user.role === "admin") {
      next();
    } else {
      res.status(403).send("You are not authorized to access this resource");
    }
  } catch (error: any) {
    res.status(401).send(`<h2>Auth Error: ${error.message}</h2>`);
  }

};



app.listen(port, () => console.log(`Listening on port ${port}...`));



// * TakeAways:
// * To avoid CORS issues, use 'Authorization' header instead (eg : 'Authorization : Bearer {token}' )

// TODOs
// encode JWT for security
// Check best practises for using express cookies with jwts (especially signed cookie)

// When authenticating manually from the Next.js frontend : (POST request to /login), You have to add `credentials: "include"` in the fetch options
// for the request to include the cookie
// The classic <form action/"login"> include the cookie by default
// TODO: check session access using an IP addess