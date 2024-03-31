import { randomBytes } from "crypto";
import express from "express";
import session from "express-session";
import cors from "cors";
import cookieParser from 'cookie-parser';
import hbs from "express-handlebars";
import { sign, verify, type JwtPayload } from 'jsonwebtoken';
const app = express();
//@ts-ignore
const port = +process.env.PORT || 8080;
const secret = 'b2d7f935b5700dc915c0260219e67cd57abeda468225b82e';
const DOMAIN = process.env.DOMAIN || 'localhost';
// const allowedOrigins = [`http://${DOMAIN}`, `https://${DOMAIN}`];
const allowedOrigins = [`http://localhost`, `http://localhost:8080`, `http://localhost:4000`];
// const allowedOrigins = /^localhost/;
app.engine('html', hbs.engine({ defaultLayout: "" }));
app.set('view engine', 'html');
app.set('views', './public');

app.use(cors({
  credentials: true,
  origin: allowedOrigins
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(cookieParser());

const sessionMaxAge = 60; // 20 seconds

app.use(session({
  secret: secret,
  name: 'jwt',
  cookie: {
    httpOnly: true,
    maxAge: sessionMaxAge,
    domain: DOMAIN
  },
}));


// declare namespace global {
//   interface SessionData {
//     jwt: string;
//   }
// }

app.get("/", (req, res) => res.render("index", { text: true, 'lastName': 'hello' }));


app.post('/login', (req, res) => {
  const { email } = req.body;
  const { redirect } = req.query;
  console.log({ redirect });
  console.log('login attempt');
  const foundUser = getUserFromDb(email);
  if (foundUser) {
    const sid = randomBytes(16).toString('hex');
    const token = sign({ sid }, secret, { expiresIn: sessionMaxAge, subject: foundUser.email });
    usersSessions[sid] = foundUser;
    console.log(`user ${foundUser.email} just logged in.`);
    // res.cookie('jwt', token, { httpOnly: true, signed: false, maxAge: sessionMaxAge * 1000, secure: false, sameSite: "lax" });
    req.session.jwt = token;
    if (redirect) return res.redirect(redirect as string);
    // res.status(200).json({ success: true });
    res.render('dashboard', foundUser);
  } else {
    res.status(404).send("User not found");
  }
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.get('/dashboard', async (req, res) => {
  try {
    const decoded = verify(token, secret) as JwtPayload;
    const user = getUserFromSession(decoded.sub!);
    if (!user) {
      res.status(401).send("Invalid Credentials");
    } else {
      console.log(user);
      res.render('dashboard', user);
    }
  } catch (error: any) {
    res.status(401).send(`<h2>Authentication error: ${error.message}</h2>`);
  }
});

app.all('/logout', (req, res) => {
  console.log('logging out...');
  res.clearCookie('jwt');
  res.redirect('/login');
  const token = req.cookies.jwt;
  const decoded = verify(token, secret) as JwtPayload;
  delete usersSessions[decoded.sid];
  res.end();
})

app.all('/api/test', (req, res) => {
  // res.cookie('jwt', 'yep', { domain: DOMAIN }).status(200).end('done');
  const token = req.cookies.jwt;
  console.log({ foundCookie: token });
  const decodedCookie = cookieParser.signedCookie(token, secret)
  console.log({ decodedCookie });
  res.end("ok");
});

app.all('/api/protected', (req, res) => {
  // check if user has valide cookie
  console.log("POST /api/protected")
  try {
    const token = req.cookies.jwt;
    if (!token) res.status(401).send("<h3>Session cookie does not exist or has expired</h3>");
    const decoded = verify(token, secret) as JwtPayload;
    const timeUntilExpiration = decoded.exp! - (Date.now() / 1000);
    console.log(`Token expires in ${timeUntilExpiration}s`);
    if (timeUntilExpiration < 0) res.send('<h3>Token expired!</h3>')
    const user = getUserFromDb(decoded.sub as string);
    console.log(decoded.sub);
    if (user && user.admin) {
      res.send('<h2>This is a protected resource</h2>')
    } else {
      res.status(403).send("You are not authorized to access this resource");
    }
  } catch (error: any) {
    res.status(401).send(`<h2>Auth Error: ${error.message}</h2>`);
  }

})

const getUserFromDb = (email: string) => {
  if (email === 'admin') return { email, name: 'Admin', admin: true };
  if (email === 'abds') return { email, name: 'abds' };
  return null;
}

const getUserFromSession = (sid: string) => {
  return usersSessions[sid];
}


const usersSessions: Record<string, { email: string, name: string }> = {
}


app.listen(port, () => console.log(`Listening on port ${port}...`));



// * TakeAways:
// * To avoid CORS issues, use 'Authorization' header instead (eg : 'Authorization : Bearer {token}' )


// Todos
// encode JWT for security
// Check best practises for using express cookies with jwts (especially signed cookie)

// When authenticating manually from the Next.js frontend : (POST request to /login), You have to add `credentials: "include"` in the fetch options
// for the request to include the cookie
// The classic <form action/"login"> include the cookie by default