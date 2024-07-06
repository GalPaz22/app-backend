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
import { OpenAIEmbeddings } from "@langchain/openai";

const pinecone = new Pinecone({
  apiKey: process.env.PINECONE_API_KEY,
});

const sessionID = uuidv4();
const pineconeIndex = pinecone.Index("index");

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
    origin: "https://www.freechatpdf.com",
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


// New endpoint to embed and store the document
app.post("/embed-pdf", upload.single("file"), async (req, res) => {
  const filePath = req.file.path;
  const { sessionId } = req.body;

  try {
    const pinecone = new Pinecone({
      apiKey: process.env.PINECONE_API_KEY,
    });

    const pineconeIndex = pinecone.Index("index");

    const pineNamespace = pineconeIndex.namespace(sessionId);
    console.log(pineNamespace);


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

    const embeddings = new OpenAIEmbeddings({
      model: "text-embedding-3-large",
      apiKey: process.env.OPENAI_API_KEY,
    });

    const documents = chunks.map(
      (chunk) =>
        new Document({
          id: uuidv4(),
          pageContent: chunk,
          metadata: { text: chunk },
        })
    );

    console.log("Documents to store:", documents);

    await PineconeStore.fromDocuments(documents, embeddings, {
      pineconeIndex,
      maxConcurrency: 5,
      namespace: sessionId,
    });

    fs.unlink(filePath, (err) => {
      if (err) {
        console.error("Error deleting file:", err);
      }
    });

    res.json({
      sessionID: sessionID,
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
  const { question, sessionId } = req.body;

  try {
    const embeddings = new OpenAIEmbeddings({
      model: "text-embedding-3-large",
      apiKey: process.env.OPENAI_API_KEY,
    });

    const questionEmbedding = await embeddings.embedQuery(question);
    console.log("Question Embedding:", questionEmbedding);

    const queryResponse = await pineconeIndex.namespace(sessionId).query({
      topK: 10,
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

    const inputText = `You are an AI assistant that answers based on pdf doceuments the user provides you. answer using the same language you get in the question. give a clean answer according to the question and the context which is retrieved from the chunks.\n\n${relevantChunks.join(
      "\n"
    )}\n\nQuestion: ${question}\n\nAnswer:`;

    const model = new ChatAnthropic({
      apiKey: process.env.ANTHROPIC_API_KEY,
      model: "claude-3-5-sonnet-20240620",
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




app.post('/clean-namespace', async (req, res) => {
  try {
    const { sessionId } = req.body;
    
    // Assuming you're using the Pinecone JavaScript client
    const pinecone = new Pinecone();
    const index = pinecone.Index("index");
    const namespace = index.namespace(sessionId);


    // Delete all vectors in the namespace
    await namespace.deleteAll();

    res.status(200).json({ message: 'Namespace cleaned successfully' });
  } catch (error) {
    console.error('Error cleaning namespace:', error);
    res.status(500).json({ error: 'An error occurred while cleaning the namespace' });
  }
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
