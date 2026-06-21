require("dotenv").config(); // Loads the MONGODB_URI from your .env file
const express = require("express");
const { MongoClient, ServerApiVersion } = require("mongodb");

const app = express();
const port = process.env.PORT || 5000;
const uri = process.env.MONGODB_URI;

// Middleware to parse JSON bodies (highly recommended for Express apps)
app.use(express.json());

// Initialize MongoDB Client
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

let db;

// Connect to MongoDB and start the server
async function startServer() {
  try {
    console.log("Connecting to MongoDB Atlas...");
    await client.connect();

    // Verify connection
    await client.db("admin").command({ ping: 1 });
    console.log("✓ Successfully connected to MongoDB!");

    // Optional: Assign a default database instance to use across your routes
    // db = client.db("your_database_name");

    // Start Express listener ONLY after DB connection succeeds
    app.listen(port, () => {
      console.log(`✓ Express server running on port ${port}`);
    });
  } catch (error) {
    console.error("✕ Failed to connect to the database:", error);
    process.exit(1); // Stop the application if DB connection fails
  }
}

// Basic Sample Route
app.get("/", (req, res) => {
  res.send("Hello World! The server is up and database is connected.");
});

// Start execution
startServer();

// Gracefully shut down DB connections when the server stops
process.on("SIGINT", async () => {
  await client.close();
  console.log("\nMongoDB connection closed. Server shutting down.");
  process.exit(0);
});
