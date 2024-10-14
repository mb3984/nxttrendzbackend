require("dotenv").config(); // Load environment variables from .env
const express = require("express");
const { ObjectId, MongoClient } = require("mongodb");
const cors = require("cors");
const bcryptjs = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

// CORS configuration
const corsOptions = {
  origin: "http://localhost:3004", // Specify your frontend's origin
  credentials: true, // Allow credentials to be included in CORS requests
};
app.use(cors(corsOptions));

const PORT = process.env.PORT || 4000; // Render provides its own PORT or use 4000 locally

let client;
const initializeDBAndServer = async () => {
  const uri = process.env.MONGODB_URI; // Use the MongoDB URI from environment variables
  client = new MongoClient(uri);

  try {
    await client.connect();
    console.log("Connected to MongoDB.....");
  } catch (error) {
    console.error("Error connecting to MongoDB:", error);
    process.exit(1); // Exit if there's an error with the database connection
  }
};

initializeDBAndServer();

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Middleware for token authentication
const authenticateToken = (request, response, next) => {
  const authHeader = request.headers["authorization"];
  if (authHeader) {
    const jwtToken = authHeader.split(" ")[1];
    jwt.verify(jwtToken, process.env.JWT_SECRET, (error, payload) => {
      if (error) {
        console.log("JWT verification error:", error);
        return response.status(401).send({ error: "Invalid JWT Token" });
      }
      request.userId = payload.userId;
      next();
    });
  } else {
    response.status(401).send({ error: "Authorization header missing" });
  }
};

// Route for user registration
app.post("/register", async (request, response) => {
  try {
    const collection = client.db("authentication").collection("users");
    const userDetails = request.body;
    const { email } = userDetails;
    const isUserExist = await collection.findOne({ email });

    if (!isUserExist) {
      const hashedPassword = await bcryptjs.hash(userDetails.password, 10);
      userDetails.password = hashedPassword;
      const result = await collection.insertOne(userDetails);
      response.status(200).send({
        yourId: result.insertedId,
        message: "User registered successfully",
      });
    } else {
      response
        .status(401)
        .send({ errorMsg: "User with this Email ID already exists" });
    }
  } catch (error) {
    console.log("Registration error:", error);
    response.status(500).send({ error: "Internal server error" });
  }
});

// Route for user login
app.post("/login", async (request, response) => {
  try {
    const collection = client.db("authentication").collection("users");
    const { email, password } = request.body;
    const user = await collection.findOne({ email });

    if (!user) {
      return response
        .status(401)
        .send({ errorMsg: "User with this Email ID doesn't exist" });
    }

    const isPasswordMatched = await bcryptjs.compare(password, user.password);
    if (isPasswordMatched) {
      const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET); // Sign token using JWT_SECRET
      response.status(200).send({ jwtToken: token, userId: user._id });
      console.log("User logged in successfully");
    } else {
      response.status(401).send({ errorMsg: "Incorrect password" });
      console.log("Incorrect password");
    }
  } catch (error) {
    console.log("Login error:", error);
    response.status(500).send({ error: "Internal server error" });
  }
});

// Route to get user data
app.get(
  "/getUserData/:userId",
  authenticateToken,
  async (request, response) => {
    try {
      const collection = client.db("authentication").collection("users");
      const { userId } = request.params;
      const user = await collection.findOne({ _id: new ObjectId(userId) });

      if (user) {
        console.log("User found:", user); // Log user object for debugging
        response.status(200).send({ username: user.name || "No name found" });
        console.log({ username: user.name }, userId);
      } else {
        response.status(404).send({ error: "User not found" });
      }
    } catch (error) {
      console.log("Error fetching user data:", error);
      response.status(500).send({ error: "Internal server error" });
    }
  }
);

// Welcome route
app.use("/", (req, res) => {
  res.send("Welcome to Nxttrendz Backend Project Madhu");
});

module.exports = app;
