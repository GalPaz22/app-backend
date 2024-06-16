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
import { ChatAnthropic } from "@langchain/anthropic";
import { PDFLoader } from "@langchain/community/document_loaders/fs/pdf";
import MongoStore from "connect-mongo";
import { RecursiveCharacterTextSplitter } from "@langchain/textsplitters";
import { Pinecone } from "@pinecone-database/pinecone";
import { PineconeStore } from "@langchain/pinecone";
import { Document } from "@langchain/core/documents";
import { CohereEmbeddings } from "@langchain/cohere";
import OpenAI from "openai";

const pinecone = new Pinecone({
  apiKey: process.env.PINECONE_API_KEY,
});

const sessionID = uuidv4();
const pineconeIndex = pinecone.Index("index");
const pineNamespace = pineconeIndex.namespace(sessionID);

const app = express();
const port = 4000;
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
    origin: "https://ask-your-doc.vercel.app",
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
        maxAge: 1000 * 60 * 60,
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
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).send("Email and password are required");

  try {
    const db = client.db("Cluster0");
    const usersCollection = db.collection("users");
    const sessionsCollection = client.db("test").collection("sessions");

    const user = await usersCollection.findOne({ email });

    if (!user) return res.status(404).send("User not found");

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(403).send("Invalid credentials");

    if (user.activeSession) {
      const activeSession = await sessionsCollection.findOne({
        sessionID: user.activeSession,
      });
      if (activeSession) {
        if (activeSession.expiresAt < new Date()) {
          await usersCollection.updateOne(
            { _id: user._id },
            { $unset: { activeSession: "" } }
          );
        } else {
          return res.status(400).send("User is already logged in");
        }
      }
    }

    const expiresAt = new Date(Date.now() + 60 * 60 * 1000);
    await usersCollection.updateOne(
      { _id: user._id },
      { $set: { activeSession: sessionID } }
    );

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

  const userId = authHeader.split(" ")[1];
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

    const user = await usersCollection.findOne({ activeSession: sessionID });

    await pineNamespace.deleteAll({deleteAll: true}); 

    if (!user) return res.status(404).send("User not found");

    if (user.activeSession) {
      await usersCollection.updateOne(
        { _id: user._id },
        { $unset: { activeSession: "" } }
      );

      await sessionsCollection.deleteOne({ activeSession: sessionID });

      res.send("Logout successful");
    }
  } catch (error) {
    console.error("Error during logout:", error);
    res.status(500).send("Internal Server Error");
  }
});

// New endpoint to embed and store the document
app.post("/embed-pdf", upload.single("file"), async (req, res) => {
  const filePath = req.file.path;
  // Generate a unique session ID for this document

  try {
    pineNamespace.deleteAll()
    const loader = new PDFLoader(filePath, { splitPages: false });
    const docs = await loader.load();
    if (!docs || docs.length === 0 || !docs[0].pageContent) {
      throw new Error("Failed to load PDF or no content found");
    }
    const pdfText = docs[0].pageContent;

    const textSplitter = new RecursiveCharacterTextSplitter({
      chunkSize: 500,
      chunkOverlap: 200,
    });
    const chunks = await textSplitter.splitText(pdfText);

    const embeddings = new CohereEmbeddings({
      apiKey: process.env.COHERE_API_KEY,
      batchSize: 48,
    });

    const documents = chunks.map(
      (chunk) =>
        new Document({
          id: `${sessionID}`,
          pageContent: chunk,
          metadata: { text: chunk },
        })
    );

    console.log("Documents to store:", documents);

    await PineconeStore.fromDocuments(documents, embeddings, {
      pineconeIndex,
      maxConcurrency: 5,
      namespace: sessionID,
    });

    fs.unlink(filePath, (err) => {
      if (err) {
        console.error("Error deleting file:", err);
      }
    });

    res.json({
      sessionId: sessionID,
      message: "PDF embedded and stored successfully",
    });
  } catch (error) {
    console.error("Error embedding PDF:", error);
    fs.unlink(filePath, (err) => {
      if (err) {
        console.error("Error deleting file:", err);
      }
    });
    res.status(500).send("An error occurred while embedding the PDF.");
  }
});

// Endpoint to generate a response based on a stored PDF
app.post("/generate-response", async (req, res) => {
  const { question, apiKey } = req.body;

  try {
    const embeddings = new CohereEmbeddings({
      apiKey: process.env.COHERE_API_KEY,
      batchSize: 48,
    });

    const questionEmbedding = await embeddings.embedQuery(question);
    console.log("Question Embedding:", questionEmbedding);

    const queryResponse = await pineNamespace.query({
      topK: 5,
      vector: questionEmbedding,
      includeMetadata: true,
    });

    console.log("Query Response:", queryResponse);

    const relevantChunks = queryResponse.matches.map(
      (match) => match.metadata.text
    );
    console.log("Relevant Chunks:", relevantChunks);

    if (!relevantChunks.length) {
      throw new Error("No relevant chunks retrieved from Pinecone");
    }

    const inputText = `Answer in the same language you got in your PDF context, in detail. 
    You'll get graphs and charts sometimes, try to find them in the document.
    Sometimes you add predicted user prompts to the answer by your own,
    don't ever do that. Just give a clean answer according to the question and the context,
    which is retrieved from the chunks.\n\n${relevantChunks.join(
      "\n"
    )}\n\nQuestion: ${question}\n\nAnswer:`;

    const model = new ChatAnthropic({
      apiKey: apiKey,
      model: "claude-3-sonnet-20240229",
    });

    const response = await model.invoke(inputText);
    const content = response.text.trim();

    res.json({ answer: content });
  } catch (error) {
    console.error("Error generating response:", error);
    res.status(500).send("An error occurred while generating the response.");
  }
});

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

const conversations = {};

app.post("/chat-response", async (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).send("Message is required");

  try {
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");

    const currentSessionId = req.sessionID || uuidv4();

    let conversation = conversations[currentSessionId];
    if (!conversation) {
      conversation = { sessionId: currentSessionId, history: [] };
      conversations[currentSessionId] = conversation;
    }

    conversation.history.push({ role: "user", text: message });

    let input =
      "You are a chatbot. You will answer in English or Hebrew, depending on the question language you receive.\n";
    for (const entry of conversation.history) {
      input += entry.role + ": " + entry.text + "\n";
    }
    input += message;

    const stream = await openai.chat.completions.create({
      model: "gpt-4o-2024-05-13",
      messages: [{ role: "user", content: input }],
      stream: true,
      temperature: 0.9,
    });

    let assistantMessage = "";

    for await (const token of stream) {
      if (token.choices[0].delta.content !== undefined) {
        assistantMessage += token.choices[0].delta.content;
        res.write(
          `data: ${JSON.stringify(token.choices[0].delta.content)}\n\n`
        );
      }
    }

    conversation.history.push({ role: "assistant", text: assistantMessage });

    res.write(`data: ${JSON.stringify("[DONE]")}\n\n`);
    res.end();
  } catch (error) {
    console.error("Error during chat:", error);
    res.status(500).send("Internal Server Error");
  }
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
