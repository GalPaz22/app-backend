import "dotenv/config";
import express from "express";
import session from "express-session";
import bodyParser from "body-parser";
import cors from "cors";
import bcrypt from "bcrypt";
import { MongoClient, ObjectId } from "mongodb";
import multer from "multer";
import fs from "fs";
import { v4 as uuidv4 } from "uuid";
import { ChatAnthropicMessages } from "@langchain/anthropic";
import { PDFLoader } from "@langchain/community/document_loaders/fs/pdf";
import MongoStore from "connect-mongo";
import { HfInference} from "@huggingface/inference";
import  {RecursiveCharacterTextSplitter}  from "@langchain/textsplitters";



const app = express();
const port = 4000;
const sessionID = uuidv4();
const apiKey = process.env.API_KEY; // Use a strong secret key and store it securely
const mongoUri = process.env.MONGO_URI;
const client = new MongoClient(mongoUri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

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
    origin: "https://ask-your-doc.vercel.app",  // Your frontend URL
    credentials: true,
    optionsSuccessStatus: 200,
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization", "sessionID"],
    
  })
);

app.use(
  session({
    secret: Math.random().toString(36).substring(2),
    resave: false,
    saveUninitialized: true,
    store: MongoStore.create({
      clientPromise: client.connect(),
      cookie: {
        maxAge: 1000 * 60 * 60 ,
        secure: true, 
        sameSite: "none",  
        httpOnly: true, 
            
      },
    }),
  })
);

const upload = multer({ dest: "uploads/" });
const sessionMemory = {};

app.post("/login", async (req, res) => {
  const { email, password, } = req.body;
  if (!email || !password)
    return res.status(400).send("Email and password are required");

  try {
    const db = client.db("Cluster0"); // Update with your main database name
    const usersCollection = db.collection("users");
    const sessionsCollection = client.db("test").collection("sessions");

    const user = await usersCollection.findOne({ email });

    if (!user) return res.status(404).send("User not found");

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(403).send("Invalid credentials");
    
    // Check if the user has an active session
    if (user.activeSession) {
      // Check if the session exists in the sessions collection and if it's expired
      const activeSession = await sessionsCollection.findOne({
        sessionID: user.activeSession,
      });
      if (activeSession) {
        if (activeSession.expiresAt < new Date()) {
          // If the session is expired, remove it from the user document
          await usersCollection.updateOne(
            { _id: user._id },
            { $unset: { activeSession: "" } }
          );
        } else {
          return res.status(400).send("User is already logged in");
        }
      }
    } // Use a UUID library to generate a unique session ID

    // Generate a new session ID
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 24 hours

    // Update user's active session
    await usersCollection.updateOne(
      { _id: user._id },
      { $set: { activeSession: sessionID } }
    );

    // Create a new session document in the sessions collection
    await sessionsCollection.insertOne({
      sessionID,
      userID: user._id,
      expiresAt,
    });

    res.send("Login successful");
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).send("Internal Server Error");
  }
});

app.get("/check-auth", (req, res) => {
  const authHeader = req.headers["authorization"];
  const db = client.db("Cluster0");
  const usersCollection = db.collection("users");
  if (!authHeader) {
    return res.status(401).json({ authenticated: false });
  }

  const userId = authHeader.split(" ")[1]; // Assuming the format is 'Bearer userId'
  if (userId) {
    return res.json({ authenticated: true });
  } else {
    usersCollection.updateOne(
      { _id: user._id },
      { $unset: { activeSession: "" } }
    );
    return res.status(401).json({ authenticated: false });
  }
});

app.post("/logout", async (req, res) => {

  try {
  const db = client.db("Cluster0");
  const usersCollection = db.collection("users");
  const sessionsCollection = client.db("test").collection("sessions");
  const user = await usersCollection.findOne({activeSession: sessionID} );
  
  if (!user) return res.status(404).send("User not found");
  
  if (user.activeSession) {
    // Remove the active session from the user document
    await usersCollection.updateOne(
      { _id: user._id },
      { $unset: { activeSession: "" } }
    );
  
    // Delete the session document from the sessions collection
    await sessionsCollection.deleteOne({ sessionID: user.activeSession });
  
    res.send("Logout successful");
  }

  } catch (error) {
  console.error("Error during logout:", error);
  res.status(500).send("Internal Server Error");
  }
  });


  app.post("/generate-response", upload.single("file"), async (req, res) => {
    const { question, sessionId } = req.body;
    const filePath = req.file.path;
    const dbName = "Cluster0";
    const collectionName = "documents";
   

    try {
      const loader = new PDFLoader(filePath);
      const docs = await loader.load();
      const pdfText = docs[0].pageContent;
      const currentSessionId = sessionId || uuidv4();
  
      const textSplitter = new RecursiveCharacterTextSplitter({ chunkSize: 1000, chunkOverlap: 100 });
      const splitDocs = await textSplitter.splitText(pdfText);
  
      // Create a MongoDB client
      
      await client.connect();
      const db = client.db(dbName);
      const collection = db.collection(collectionName);
  
      // Generate embeddings for split documents and insert them into MongoDB
      for (const doc of splitDocs) {
        const model = new HfInference({
          model: "sentence-transformers/all-MiniLM-L6-v2",
          
        });
        const embedding = await model.embed(doc);
        await collection.insertOne({ text: doc, embedding });
      }
  
      const conversationHistory = sessionMemory[currentSessionId] || [];
      conversationHistory.push(`User: ${question}`);
  
      // Generate embedding for the question
      const model = new HfInference({
        model: "sentence-transformers/all-MiniLM-L6-v2",

      });
      const questionEmbedding = await model.embed(question);
  
      // Query MongoDB for relevant documents based on the question embedding
      const relevantDocs = await collection
        .find({
          embedding: { $nearSphere: { $geometry: questionEmbedding, $maxDistance: 0.5 } },
        })
        .limit(5)
        .toArray();
  
      const context = relevantDocs.map((doc) => doc.text).join("\n\n");
  
      const inputText = `Answer in the same language you got in your PDF context, in detail. you'll get graphs and charts sometimes, try to find them in the document. answer in academic manner, and dont include other question by your own- answer only to the question you've got\n\n${context}\n\n${conversationHistory.join(
        "\n"
      )}\nAssistant:`;
  
      const chatModel = new ChatAnthropicMessages({
        apiKey: apiKey,
        model: "claude-3-sonnet-20240229",
      });
  
      const response = await chatModel.invoke(inputText);
      const content = response.text.trim();
      conversationHistory.push(`Assistant: ${content}`);
      sessionMemory[currentSessionId] = conversationHistory;
  
      fs.unlink(filePath, (err) => {
        if (err) {
          console.error("Error deleting file:", err);
        }
      });
  
      res.json({ sessionId: currentSessionId, answer: content });
    } catch (error) {
      console.error("Error generating response:", error);
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
