import express from "express";
import bodyParser from "body-parser";
import cors from "cors";
import multer from "multer";
import fs from "fs";
import { ChatAnthropicMessages } from "@langchain/anthropic";
import { PDFLoader } from "@langchain/community/document_loaders/fs/pdf";
import { v4 as uuidv4 } from "uuid";
import bcrypt from "bcrypt";
import session from "express-session";
import { MongoClient } from "mongodb";

process.env.ANTHROPIC_API_KEY =
  "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";
const uri =
  "mongodb+srv://galpaz2210:jGqI4pEv3gZuJTCc@cluster0.qiplrsq.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";

const client = new MongoClient(uri);

const app = express();
const port = 4000;
const SECRET_KEY = "your_secret_key"; // Use a strong secret key and store it securely

client
  .connect()
  .then(() => {
    console.log("Connected to MongoDB");
  })
  .catch((err) => {
    console.error("Error connecting to MongoDB:", err);
  });

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(
  cors({
    origin: "http://localhost:3000", // Change this to your frontend URL
    credentials: true,
  })
);

app.use(
  session({
    secret: SECRET_KEY,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }, // Set to true if using HTTPS
  })
);

const upload = multer({ dest: "uploads/" });
const sessionMemory = {};

// User login endpoint
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).send("Email and password are required");

  try {
    const db = client.db("Cluster0"); // Update with your database name
    const usersCollection = db.collection("users");

    // Query MongoDB for the user with the provided email
    const user = await usersCollection.findOne({ email });

    if (!user) return res.status(404).send("User not found");

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(403).send("Invalid credentials");

    req.session.userId = user._id; // Assuming you have a field named _id for user identification
    res.send({ message: "Logged in successfully", redirectTo: "/ask" });
  } catch (error) {
    console.error("Error logging in:", error);
    res.status(500).send("An error occurred while logging in.");
  }
});

app.get("/check-auth", (req, res) => {
  if (req.session.userId) {
    return res.json({ authenticated: true });
  } else {
    return res.status(401).json({ authenticated: false });
  }
});

// Logout endpoint
app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send("Could not log out");
    } else {
      res.send("Logged out successfully");
    }
  });
});

// Middleware to check if the user is authenticated
const authenticate = (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).send("Not authenticated");
  }
  next();
};

// Generate response endpoint
app.post("/generate-response", upload.single("file"), async (req, res) => {
  const { question, sessionId } = req.body;
  const filePath = req.file.path; // This is the path to the uploaded file

  const currentSessionId = sessionId || uuidv4();

  try {
    const loader = new PDFLoader(filePath);
    const docs = await loader.load();
    const pdfText = docs[0].pageContent;

    const conversationHistory = sessionMemory[currentSessionId] || [];
    conversationHistory.push(`User: ${question}`);

    const inputText = `${pdfText}\n\n${conversationHistory.join(
      "\n"
    )}\nAssistant:`;

    const model = new ChatAnthropicMessages({
      apiKey: process.env.ANTHROPIC_API_KEY,
      model: "claude-1.3",
    });

    const response = await model.invoke(inputText);

    const content = response.text.trim();
    conversationHistory.push(`Assistant: ${content}`);
    sessionMemory[currentSessionId] = conversationHistory;

    // Delete the uploaded file
    fs.unlink(filePath, (err) => {
      if (err) {
        console.error("Error deleting file:", err);
      }
    });

    res.json({ sessionId: currentSessionId, answer: content });
  } catch (error) {
    console.error("Error generating response:", error);
    // Delete the uploaded file in case of error as well
    fs.unlink(filePath, (err) => {
      if (err) {
        console.error("Error deleting file:", err);
      }
    });
    res.status(500).send("An error occurred while generating the response.");
  }
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
