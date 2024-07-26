const express = require("express");
const path = require("path");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const multer = require("multer");
const { v2 } = require("cloudinary");
const fs = require("fs");
const http = require("http");
const { v4: uuidv4 } = require("uuid");
require("dotenv").config();
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const ejs = require("ejs");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const cors = require("cors");
const FormData = require("form-data");
const fetch = require("node-fetch");

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.set("trust proxy", true);

app.use(
  cors({
    origin: [
      "http://localhost:3000",
      "https://youtube-proxy-frontend.onrender.com",
    ],
    methods: "GET,POST,PUT,DELETE",
    credentials: true,
  })
);

const sessionDBPath = path.join(__dirname, "database", "sessions.db");

let db = null;
async function initializeSessionDatabase() {
  try {
    db = await open({
      filename: sessionDBPath,
      driver: sqlite3.Database,
    });

    await db.exec(`
      CREATE TABLE IF NOT EXISTS sessions (
        sid TEXT PRIMARY KEY,
        expires INTEGER,
        sess TEXT
      );
    `);

    console.log("Session database initialized");
  } catch (error) {
    console.error("Error initializing session database:", error);
    throw error;
  }
}

initializeSessionDatabase();

const store = new SQLiteStore({
  db: "sessions.db",
  table: "sessions",
  dir: path.join(__dirname, "database"),
  createDirIfNotExists: true,
});

app.use(
  session({
    store: store,
    secret: process.env.KEY,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'none',
      maxAge: 30 * 24 * 60 * 60 * 1000,
      domain: '.onrender.com',
      path: '/'
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

app.use((req, res, next) => {
  res.header(
    "Access-Control-Allow-Origin",
    "https://youtube-proxy-frontend.onrender.com"
  );
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept"
  );
  next();
});

app.use((req, res, next) => {
  console.log("Session ID:", req.sessionID);
  console.log("Session Data:", req.session);
  next();
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.clientID,
      clientSecret: process.env.clientSecret,
      callbackURL: process.env.callbackURL,
      scope: [
        "profile",
        "email",
        "https://www.googleapis.com/auth/youtube.upload",
        "https://www.googleapis.com/auth/youtubepartner",
        "https://www.googleapis.com/auth/youtube",
        "https://www.googleapis.com/auth/youtube.force-ssl",
      ],
      accessType: "offline",
      prompt: "consent select_account",
    },
    async (accessToken, refreshToken, profile, cb) => {
      console.log("userAccessToken:", accessToken);
      console.log("userRefreshToken:", refreshToken);
      try {
        const email = profile.emails[0].value;
        const userImage = profile.photos[0].value;
        const userDisplayName = profile.displayName;

        const userCheckQuery = `SELECT * FROM users WHERE email=?;`;
        const userResponse = await mdb.get(userCheckQuery, email);

        if (!userResponse) {
          const maxIdQuery = `SELECT max(id) as maximum_id FROM users;`;
          const maxIdResponse = await mdb.get(maxIdQuery);
          const userName = `${profile.name.givenName}${(maxIdResponse.maximum_id || 0) + 1
            }`;
          const userInvitationCode = userName;

          const addUserQuery = `INSERT INTO users (username, email, invitation_code, refresh_token, user_image, user_display_name) VALUES (?, ?, ?, ?, ?, ?)`;
          await mdb.run(addUserQuery, [
            userName,
            email,
            userInvitationCode,
            refreshToken,
            userImage,
            userDisplayName,
          ]);
          console.log(`New user created: ${userName}`);
        } else {
          const updateRefreshTokenQuery = `UPDATE users SET refresh_token = ? WHERE email = ?`;
          await mdb.run(updateRefreshTokenQuery, [refreshToken, email]);
          console.log(`User updated: ${userResponse.username}`);
        }

        cb(null, email);
      } catch (err) {
        console.error("Error in GoogleStrategy:", err);
        cb(err, null);
      }
    }
  )
);

passport.serializeUser((email, cb) => {
  console.log("serializing user:", email);
  cb(null, email);
});

passport.deserializeUser(async (email, cb) => {
  console.log("deserializing user:", email);
  try {
    const getUserDetailsQuery = `SELECT * FROM users WHERE email = ?;`;
    const userDetailsObj = await mdb.get(getUserDetailsQuery, [email]);
    if (!userDetailsObj) {
      console.log("user not found");
      throw new Error("User not found");
    }
    cb(null, userDetailsObj);
  } catch (err) {
    console.error("Error in deserializeUser:", err);
    cb(err, null);
  }
});

app.get(
  "/oauth/google",
  passport.authenticate("google", {
    scope: [
      "profile",
      "email",
      "https://www.googleapis.com/auth/youtube.upload",
      "https://www.googleapis.com/auth/youtubepartner",
      "https://www.googleapis.com/auth/youtube",
      "https://www.googleapis.com/auth/youtube.force-ssl",
    ],
    accessType: "offline",
    prompt: "consent select_account",
  })
);

app.get(
  "/oauth/redirect",
  passport.authenticate("google", {
    failureRedirect: "https://youtube-proxy-frontend.onrender.com/login",
  }),
  async (request, response) => {
    response.redirect("https://youtube-proxy-frontend.onrender.com");
  }
);

v2.config({
  cloud_name: process.env.cloudName,
  api_key: process.env.apiKey,
  api_secret: process.env.apiSecret,
});

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "./uploads");
  },
  filename: function (req, file, cb) {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});

const upload = multer({
  storage,
});

const dbPath = path.join(__dirname, "youtubetimer.db");
let mdb = null;
const initializeDBAndServer = async () => {
  try {
    mdb = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });

    app.listen(5000, () => {
      console.log("server is running on http://localhost:5000");
    });
  } catch (error) {
    console.log(`error: ${error.message}`);
    process.exit(1);
  }
};

initializeDBAndServer();

const ensureAuthenticated = (request, response, next) => {
  if (request.isAuthenticated()) {
    return next();
  }
  response.redirect("/oauth/google");
};

const ensureAuthenticatedForFrontend = (request, response, next) => {
  console.log("User: ", request.user);
  console.log("request cookie:", request.headers.cookie);
  if (request.isAuthenticated()) {
    return next();
  }
  response.send({ authenticated: false });
};

const getNewAccessToken = async (refreshToken) => {
  const url = "https://oauth2.googleapis.com/token";
  const params = new URLSearchParams({
    client_id: process.env.clientID,
    client_secret: process.env.clientSecret,
    refresh_token: refreshToken,
    grant_type: "refresh_token",
  });

  try {
    const response = await fetch(url, {
      method: "POST",
      body: params,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    });

    if (!response.ok) {
      const errorData = await response.json();
      console.error("Error refreshing access token:", errorData);
      return null;
    }

    const data = await response.json();
    console.log("new AccessToken: ", data.access_token);

    return data.access_token;
  } catch (error) {
    console.error("Error refreshing access token:", error);
    return null;
  }
};

app.get("/user/details", async (request, response) => {
  if (request.isAuthenticated()) {
    console.log("user email", request.user.email);
    const query = `SELECT email, invitation_code, user_image, user_display_name FROM users WHERE email=?;`;
    const dbResponse = await mdb.get(query, request.user.email);
    console.log("dbResponse:", dbResponse);
    response.json({
      invitationCode: dbResponse.invitation_code,
      userEmail: dbResponse.email,
      userImage: dbResponse.user_image,
      userDisplayName: dbResponse.user_display_name,
    });
  } else {
    response.send({ authenticated: false });
  }
});

app.get("/logout", (request, response) => {
  request.logout((err) => {
    if (err) {
      console.error("Logout error:", err);
    }
    response.clearCookie("connect.sid");
    response.redirect("https://youtube-proxy-frontend.onrender.com");
  });
});

app.get("/get-access-token", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const getUserRefreshTokenQuery = `SELECT refresh_token FROM users WHERE email = ?;`;
      const userResponse = await mdb.get(getUserRefreshTokenQuery, req.user.email);

      if (!userResponse) {
        return res.status(404).send("User not found");
      }

      const newAccessToken = await getNewAccessToken(userResponse.refresh_token);

      if (newAccessToken) {
        res.json({ accessToken: newAccessToken });
      } else {
        res.status(500).send("Unable to fetch new access token");
      }
    } catch (error) {
      console.error("Error getting access token:", error);
      res.status(500).send("Internal Server Error");
    }
  } else {
    res.status(401).send("Unauthorized");
  }
});

app.post("/upload", upload.single("file"), async (req, res) => {
  if (!req.file) {
    return res.status(400).send("No file uploaded");
  }

  const filePath = path.join(__dirname, "uploads", req.file.filename);

  try {
    const result = await v2.uploader.upload(filePath);
    fs.unlinkSync(filePath);
    res.json({ url: result.secure_url });
  } catch (error) {
    console.error("Error uploading to Cloudinary:", error);
    res.status(500).send("Error uploading file");
  }
});

app.get("/proxy/youtube", async (req, res) => {
  const { url } = req.query;

  if (!url) {
    return res.status(400).send("URL parameter is required");
  }

  try {
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`Failed to fetch from ${url}`);
    }
    const data = await response.text();
    res.send(data);
  } catch (error) {
    console.error("Error fetching URL:", error);
    res.status(500).send("Internal Server Error");
  }
});
