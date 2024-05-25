import express from 'express';
import session from 'express-session';
import bodyParser from 'body-parser';
import cors from 'cors';
import bcrypt from 'bcrypt';
import { MongoClient } from 'mongodb';
import multer from 'multer';
import fs from 'fs';
import { v4 as uuidv4 } from 'uuid';
import { ChatAnthropicMessages } from '@langchain/anthropic';
import { PDFLoader } from '@langchain/community/document_loaders/fs/pdf';
import MongoStore from 'connect-mongo';

const app = express();
const port = 4000;
process.env.ANTHROPIC_API_KEY =
  "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";

const mongoUri = 'mongodb+srv://galpaz2210:jGqI4pEv3gZuJTCc@cluster0.qiplrsq.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
const client = new MongoClient(mongoUri, { useNewUrlParser: true, useUnifiedTopology: true });

client.connect().then(() => {
  console.log('Connected to MongoDB');
}).catch((err) => {
  console.error('Error connecting to MongoDB:', err);
});

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use(cors({
  origin: 'https://app-frontend-7846-cflc3z6hy-galpaz22s-projects.vercel.app', // Your frontend URL
  credentials: true,
}));

app.use(session({
  secret: 'your_secret_key',
  resave: false,
  saveUninitialized: true,
  store: MongoStore.create({
    clientPromise: client.connect(),
  }),
  cookie: {
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    secure: false, // Set to true if using HTTPS
    httpOnly: true,
    sameSite: 'strict',
  }
}));

const upload = multer({ dest: 'uploads/' });
const sessionMemory = {};

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).send('Email and password are required');

  try {
    const db = client.db('Cluster0'); // Update with your database name
    const usersCollection = db.collection('users');

    const user = await usersCollection.findOne({ email });

    if (!user) return res.status(404).send('User not found');

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(403).send('Invalid credentials');

    res.send({ message: 'Logged in successfully', userId: user._id });
  } catch (error) {
    console.error('Error logging in:', error);
    res.status(500).send('An error occurred while logging in.');
  }
});

app.get('/check-auth', (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    return res.status(401).json({ authenticated: false });
  }

  const userId = authHeader.split(' ')[1]; // Assuming the format is 'Bearer userId'
  if (userId) {
    return res.json({ authenticated: true });
  } else {
    return res.status(401).json({ authenticated: false });
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send('Could not log out');
    } else {
      res.send('Logged out successfully');
    }
  });
});

const authenticate = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    return res.status(401).send('Not authenticated');
  }

  const userId = authHeader.split(' ')[1];
  if (!userId) {
    return res.status(401).send('Not authenticated');
  }

  req.userId = userId; // Attach userId to request object
  next();
};

app.post('/generate-response', upload.single('file'), async (req, res) => {
  const { question, sessionId } = req.body;
  const filePath = req.file.path;

  const currentSessionId = sessionId || uuidv4();

  try {
    const loader = new PDFLoader(filePath);
    const docs = await loader.load();
    const pdfText = docs[0].pageContent;

    const conversationHistory = sessionMemory[currentSessionId] || [];
    conversationHistory.push(`User: ${question}`);
    
    const inputText = `${pdfText}\n\n${conversationHistory.join("\n")}\nAssistant:`;
    
    
    const model = new ChatAnthropicMessages({
      apiKey: process.env.ANTHROPIC_API_KEY,
      model: 'claude-1.3',
    });

   const response = await model.invoke(inputText);

   const content = response.text.trim();
    conversationHistory.push(`Assistant: ${content}`);
    sessionMemory[currentSessionId] = conversationHistory;

    fs.unlink(filePath, (err) => {
      if (err) {
        console.error('Error deleting file:', err);
      }
    });

    res.json({ sessionId: currentSessionId, answer: content });
  } catch (error) {
    console.error('Error generating response:', error);
    fs.unlink(filePath, (err) => {
      if (err) {
        console.error('Error deleting file:', err);
      }
    });
    res.status(500).send('An error occurred while generating the response.');
  }
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
