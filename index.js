require("dotenv").config();
const express = require("express");
const cors = require("cors");
const multer = require("multer");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

const app = express();
const port = process.env.PORT || 5000;
const uri = process.env.MONGODB_URI;
const dbName = process.env.MONGODB_DB_NAME || "startupforge";
const clientUrl = process.env.CLIENT_URL || "http://localhost:3000";

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
});

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

let db;

app.use(
  cors({
    origin: process.env.CORS_ORIGIN || clientUrl,
    credentials: true,
  }),
);
app.use(express.json());

async function requireAuth(req, res, next) {
  try {
    const cookie = req.headers.cookie;
    if (!cookie) {
      return res.status(401).json({ success: false, error: "Unauthorized" });
    }

    const response = await fetch(`${clientUrl}/api/auth/get-session`, {
      headers: { cookie },
    });

    const session = await response.json();
    if (!session?.user) {
      return res.status(401).json({ success: false, error: "Unauthorized" });
    }

    req.user = session.user;
    req.session = session.session;
    next();
  } catch (error) {
    console.error("Auth middleware error:", error);
    return res.status(401).json({ success: false, error: "Unauthorized" });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    const userRole = req.user?.role;
    if (!userRole || (!roles.includes(userRole) && userRole !== "Admin")) {
      return res.status(403).json({ success: false, error: "Forbidden" });
    }
    next();
  };
}

app.get("/", (req, res) => {
  res.json({ message: "StartupForge API is running" });
});

app.post("/api/images", upload.single("image"), async (req, res) => {
  try {
    if (!req.file) {
      return res
        .status(400)
        .json({ success: false, error: "No image file provided" });
    }

    const imgbbKey = process.env.IMGBB_API_KEY;
    if (!imgbbKey) {
      return res
        .status(500)
        .json({ success: false, error: "ImgBB API key not configured" });
    }

    const base64 = req.file.buffer.toString("base64");
    const body = new URLSearchParams();
    body.append("image", base64);

    const imgbbRes = await fetch(
      `https://api.imgbb.com/1/upload?key=${imgbbKey}`,
      { method: "POST", body },
    );
    const data = await imgbbRes.json();

    if (!data.success) {
      return res.status(400).json({
        success: false,
        error: data.error?.message || "Image upload failed",
      });
    }

    res.json({
      success: true,
      data: {
        url: data.data.url,
        display_url: data.data.display_url,
      },
    });
  } catch (error) {
    console.error("Image upload error:", error);
    res.status(500).json({ success: false, error: "Image upload failed" });
  }
});

app.post(
  "/api/startups",
  requireAuth,
  requireRole("Founder"),
  async (req, res) => {
    try {
      const {
        startupName,
        logo,
        industry,
        description,
        fundingStage,
        founderEmail,
      } = req.body;

      if (
        !startupName ||
        !logo ||
        !industry ||
        !description ||
        !fundingStage ||
        !founderEmail
      ) {
        return res.status(400).json({
          success: false,
          error: "All startup fields are required",
        });
      }

      const startup = {
        startupName,
        logo,
        industry,
        description,
        fundingStage,
        founderEmail,
        founderId: req.user.id,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const result = await db.collection("startups").insertOne(startup);

      res.status(201).json({
        success: true,
        data: { ...startup, _id: result.insertedId },
      });
    } catch (error) {
      console.error("Create startup error:", error);
      res.status(500).json({ success: false, error: "Failed to create startup" });
    }
  },
);

app.get("/api/startups", async (req, res) => {
  try {
    const startups = await db
      .collection("startups")
      .find({})
      .sort({ createdAt: -1 })
      .toArray();
    res.json({ success: true, data: startups });
  } catch (error) {
    console.error("List startups error:", error);
    res.status(500).json({ success: false, error: "Failed to fetch startups" });
  }
});

app.post(
  "/api/opportunities",
  requireAuth,
  requireRole("Founder"),
  async (req, res) => {
    try {
      const {
        roleTitle,
        requiredSkills,
        workType,
        commitmentLevel,
        deadline,
      } = req.body;

      if (
        !roleTitle ||
        !workType ||
        !commitmentLevel ||
        !deadline ||
        !requiredSkills?.length
      ) {
        return res.status(400).json({
          success: false,
          error: "All opportunity fields are required",
        });
      }

      const opportunity = {
        roleTitle,
        requiredSkills,
        workType,
        commitmentLevel,
        deadline: new Date(deadline),
        founderId: req.user.id,
        founderEmail: req.user.email,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const result = await db.collection("opportunities").insertOne(opportunity);

      res.status(201).json({
        success: true,
        data: { ...opportunity, _id: result.insertedId },
      });
    } catch (error) {
      console.error("Create opportunity error:", error);
      res
        .status(500)
        .json({ success: false, error: "Failed to create opportunity" });
    }
  },
);

app.get("/api/opportunities", async (req, res) => {
  try {
    const opportunities = await db
      .collection("opportunities")
      .find({})
      .sort({ createdAt: -1 })
      .toArray();
    res.json({ success: true, data: opportunities });
  } catch (error) {
    console.error("List opportunities error:", error);
    res
      .status(500)
      .json({ success: false, error: "Failed to fetch opportunities" });
  }
});

app.get("/api/opportunities/:id", async (req, res) => {
  try {
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ success: false, error: "Invalid ID" });
    }

    const opportunity = await db.collection("opportunities").findOne({
      _id: new ObjectId(req.params.id),
    });

    if (!opportunity) {
      return res
        .status(404)
        .json({ success: false, error: "Opportunity not found" });
    }

    res.json({ success: true, data: opportunity });
  } catch (error) {
    console.error("Get opportunity error:", error);
    res
      .status(500)
      .json({ success: false, error: "Failed to fetch opportunity" });
  }
});

app.post(
  "/api/applications",
  requireAuth,
  requireRole("Collaborator"),
  async (req, res) => {
    try {
      const { opportunityId, applicantEmail, portfolioLink, motivationMessage } =
        req.body;

      if (
        !opportunityId ||
        !applicantEmail ||
        !portfolioLink ||
        !motivationMessage
      ) {
        return res.status(400).json({
          success: false,
          error: "All application fields are required",
        });
      }

      if (!ObjectId.isValid(opportunityId)) {
        return res.status(400).json({ success: false, error: "Invalid opportunity ID" });
      }

      const opportunity = await db.collection("opportunities").findOne({
        _id: new ObjectId(opportunityId),
      });

      if (!opportunity) {
        return res
          .status(404)
          .json({ success: false, error: "Opportunity not found" });
      }

      const existing = await db.collection("applications").findOne({
        opportunityId,
        applicantId: req.user.id,
      });

      if (existing) {
        return res.status(409).json({
          success: false,
          error: "You have already applied to this opportunity",
        });
      }

      const application = {
        opportunityId,
        roleTitle: opportunity.roleTitle,
        applicantEmail,
        portfolioLink,
        motivationMessage,
        applicantId: req.user.id,
        applicantName: req.user.name,
        status: "Pending",
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const result = await db.collection("applications").insertOne(application);

      res.status(201).json({
        success: true,
        data: { ...application, _id: result.insertedId },
      });
    } catch (error) {
      console.error("Create application error:", error);
      res
        .status(500)
        .json({ success: false, error: "Failed to submit application" });
    }
  },
);

app.get("/api/applications", requireAuth, async (req, res) => {
  try {
    const { role } = req.user;
    let filter = {};

    if (role === "Collaborator") {
      filter = { applicantId: req.user.id };
    } else if (role === "Founder") {
      const myOpportunities = await db
        .collection("opportunities")
        .find({ founderId: req.user.id })
        .project({ _id: 1 })
        .toArray();
      const oppIds = myOpportunities.map((o) => o._id.toString());
      filter = { opportunityId: { $in: oppIds } };
    }

    const applications = await db
      .collection("applications")
      .find(filter)
      .sort({ createdAt: -1 })
      .toArray();

    res.json({ success: true, data: applications });
  } catch (error) {
    console.error("List applications error:", error);
    res
      .status(500)
      .json({ success: false, error: "Failed to fetch applications" });
  }
});

async function startServer() {
  try {
    console.log("Connecting to MongoDB Atlas...");
    await client.connect();
    await client.db("admin").command({ ping: 1 });
    db = client.db(dbName);
    console.log(`✓ Connected to database: ${dbName}`);

    app.listen(port, () => {
      console.log(`✓ Express server running on port ${port}`);
    });
  } catch (error) {
    console.error("✕ Failed to connect to the database:", error);
    process.exit(1);
  }
}

startServer();

process.on("SIGINT", async () => {
  await client.close();
  console.log("\nMongoDB connection closed. Server shutting down.");
  process.exit(0);
});
