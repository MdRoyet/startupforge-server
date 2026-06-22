require("dotenv").config();
const express = require("express");
const cors = require("cors");
const multer = require("multer");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

const app = express();
const port = process.env.PORT || 5000;
const uri = process.env.MONGODB_URI;

const dbName = process.env.MONGODB_DB_NAME || "startupforgeDB";
const clientUrl = process.env.CLIENT_URL || "http://localhost:3000";

// Multer memory buffer configuration (Max 5MB)
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

// CORS configuration supporting dynamic credential passing
app.use(
  cors({
    origin: process.env.CORS_ORIGIN || clientUrl,
    credentials: true,
  }),
);
app.use(express.json());

// --- Authentication Middleware ---
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

// --- Role-Based Access Control Middleware ---
function requireRole(...roles) {
  return (req, res, next) => {
    const userRole = req.user?.role;
    if (!userRole || (!roles.includes(userRole) && userRole !== "Admin")) {
      return res.status(403).json({ success: false, error: "Forbidden" });
    }
    next();
  };
}

// Base Route
app.get("/", (req, res) => {
  res.json({ message: "StartupForge API is running" });
});

// --- Secure Image Upload Route (ImgBB Bridge) ---
app.post("/api/images", upload.single("image"), async (req, res) => {
  try {
    if (!req.file) {
      return res
        .status(400)
        .json({ success: false, error: "No image file provided" });
    }

    const imgbbKey = process.env.IMGBB_API_KEY;
    if (!imgbbKey) {
      return res.status(500).json({
        success: false,
        error: "Server configuration missing: ImgBB API key not found.",
      });
    }

    const blob = new Blob([req.file.buffer], { type: req.file.mimetype });
    const formData = new FormData();
    formData.append("image", blob, req.file.originalname);

    const imgbbRes = await fetch(
      `https://api.imgbb.com/1/upload?key=${imgbbKey}`,
      {
        method: "POST",
        body: formData,
      },
    );

    const data = await imgbbRes.json();

    if (!data.success) {
      return res.status(400).json({
        success: false,
        error:
          data.error?.message || "Image upload rejected by hosting provider.",
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
    console.error("Image upload exception details:", error);
    res.status(500).json({
      success: false,
      error: `Internal execution error: ${error.message}`,
    });
  }
});

// ==========================================
// --- STARTUPS CRUD MANAGEMENT MODULE ---
// ==========================================

// Create Startup Profile
app.post(
  "/api/startups",
  requireAuth,
  requireRole("Founder"),
  async (req, res) => {
    try {
      const startupsCollection =
        req.app.locals.startups || db.collection("startups");
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
        return res
          .status(400)
          .json({ success: false, error: "All startup fields are required" });
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

      const result = await startupsCollection.insertOne(startup);

      res.status(201).json({
        success: true,
        data: { ...startup, _id: result.insertedId },
      });
    } catch (error) {
      console.error("Create startup error:", error);
      res
        .status(500)
        .json({ success: false, error: "Failed to create startup" });
    }
  },
);

// Fetch All Startups Owned By Currently Logged In Founder
app.get(
  "/api/startups/me",
  requireAuth,
  requireRole("Founder"),
  async (req, res) => {
    try {
      const startupsCollection =
        req.app.locals.startups || db.collection("startups");
      const startups = await startupsCollection
        .find({ founderId: req.user.id })
        .sort({ createdAt: -1 })
        .toArray();

      res.json({ success: true, data: startups });
    } catch (error) {
      console.error("Fetch profile error:", error);
      res
        .status(500)
        .json({ success: false, error: "Failed to fetch startup data." });
    }
  },
);

// Public Endpoint: Fetch All Registered Startups across ecosystem nodes
app.get("/api/startups", async (req, res) => {
  try {
    const startupsCollection =
      req.app.locals.startups || db.collection("startups");
    const startups = await startupsCollection
      .find({})
      .sort({ createdAt: -1 })
      .toArray();
    res.json({ success: true, data: startups });
  } catch (error) {
    console.error("List startups error:", error);
    res.status(500).json({ success: false, error: "Failed to fetch startups" });
  }
});

// Update Existing Startup Profile metrics
app.put(
  "/api/startups/:id",
  requireAuth,
  requireRole("Founder"),
  async (req, res) => {
    try {
      const startupsCollection =
        req.app.locals.startups || db.collection("startups");
      const startupId = req.params.id;
      const {
        startupName,
        logo,
        industry,
        description,
        fundingStage,
        founderEmail,
      } = req.body;

      if (!ObjectId.isValid(startupId)) {
        return res
          .status(400)
          .json({ success: false, error: "Invalid target startup ID format." });
      }

      const filter = { _id: new ObjectId(startupId), founderId: req.user.id };
      const updatedDocument = {
        $set: {
          startupName,
          logo,
          industry,
          description,
          fundingStage,
          founderEmail,
          updatedAt: new Date(),
        },
      };

      const updateResult = await startupsCollection.updateOne(
        filter,
        updatedDocument,
      );

      if (updateResult.matchedCount === 0) {
        return res.status(404).json({
          success: false,
          error:
            "Startup profile not found or unauthorized modification attempt.",
        });
      }

      const freshDocument = await startupsCollection.findOne({
        _id: new ObjectId(startupId),
      });
      res.status(200).json({
        success: true,
        message: "Startup credentials synchronized successfully.",
        data: freshDocument,
      });
    } catch (error) {
      console.error("CRITICAL DB Update Exception:", error);
      res.status(500).json({
        success: false,
        error: "Internal server update error pipeline failed.",
      });
    }
  },
);

// Delete Startup Profile permanently
app.delete(
  "/api/startups/:id",
  requireAuth,
  requireRole("Founder"),
  async (req, res) => {
    try {
      const startupsCollection =
        req.app.locals.startups || db.collection("startups");
      const startupId = req.params.id;

      if (!ObjectId.isValid(startupId)) {
        return res
          .status(400)
          .json({ success: false, error: "Invalid target startup ID format." });
      }

      const result = await startupsCollection.deleteOne({
        _id: new ObjectId(startupId),
        founderId: req.user.id,
      });

      if (result.deletedCount === 0) {
        return res.status(404).json({
          success: false,
          error:
            "Target startup asset records not found or unauthorized deletion attempt.",
        });
      }

      res.status(200).json({
        success: true,
        message: "Startup asset permanently removed from database indexes.",
      });
    } catch (error) {
      console.error("DB Deletion Exception:", error);
      res.status(500).json({
        success: false,
        error: "Internal server deletion pipeline failed.",
      });
    }
  },
);

// =============================================
// --- OPPORTUNITIES CRUD MANAGEMENT MODULE ---
// =============================================

// Post New Position Opportunity
// --- POST: CREATE OPPORTUNITY UNDER A SPECIFIC STARTUP ---
app.post(
  "/api/opportunities",
  requireAuth,
  requireRole("Founder"),
  async (req, res) => {
    try {
      const opportunitiesCollection =
        req.app.locals.opportunities || db.collection("opportunities");
      const startupsCollection =
        req.app.locals.startups || db.collection("startups");

      const {
        startupId,
        roleTitle,
        requiredSkills,
        workType,
        commitmentLevel,
        deadline,
        industry,
      } = req.body;

      // 1. Validation Check
      if (
        !startupId ||
        !roleTitle ||
        !workType ||
        !commitmentLevel ||
        !deadline ||
        !requiredSkills?.length
      ) {
        return res.status(400).json({
          success: false,
          error:
            "All fields, including corporate company assignment selection, are required.",
        });
      }

      if (!ObjectId.isValid(startupId)) {
        return res
          .status(400)
          .json({
            success: false,
            error: "Malformed Startup ID alignment schema.",
          });
      }

      // 2. Security Check: Verify this startup belongs to the logged-in founder
      const startup = await startupsCollection.findOne({
        _id: new ObjectId(startupId),
        founderId: req.user.id,
      });

      if (!startup) {
        return res.status(403).json({
          success: false,
          error:
            "Access Denied: You do not hold ownership privileges for this corporate profile.",
        });
      }

      // 3. Build Relational Object Structure
      const opportunity = {
        startupId: new ObjectId(startupId),
        startupName: startup.startupName, // Embedded denormalized value for rapid performance loading
        startupLogo: startup.logo, // Embedded denormalized value for rapid performance loading
        roleTitle,
        requiredSkills,
        workType,
        commitmentLevel,
        deadline: new Date(deadline),
        industry: industry || startup.industry || "General",
        founderId: req.user.id,
        founderEmail: req.user.email,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const result = await opportunitiesCollection.insertOne(opportunity);

      res.status(201).json({
        success: true,
        message:
          "Opportunity posted under corporate umbrella records successfully.",
        data: { ...opportunity, _id: result.insertedId },
      });
    } catch (error) {
      console.error("Create opportunity relational mapping error:", error);
      res
        .status(500)
        .json({
          success: false,
          error: "Failed to link and create opportunity.",
        });
    }
  },
);

// Public Endpoint: Fetch All Registered Opportunities
app.get("/api/opportunities", async (req, res) => {
  try {
    const opportunitiesCollection =
      req.app.locals.opportunities || db.collection("opportunities");
    const opportunities = await opportunitiesCollection
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

// Lookup Singular Specific Opportunity Details
app.get("/api/opportunities/:id", async (req, res) => {
  try {
    const opportunitiesCollection =
      req.app.locals.opportunities || db.collection("opportunities");
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ success: false, error: "Invalid ID" });
    }

    const opportunity = await opportunitiesCollection.findOne({
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

// Update Existing Opportunity Posting metrics
app.put(
  "/api/opportunities/:id",
  requireAuth,
  requireRole("Founder"),
  async (req, res) => {
    try {
      const opportunitiesCollection =
        req.app.locals.opportunities || db.collection("opportunities");
      const targetId = req.params.id;
      const {
        roleTitle,
        requiredSkills,
        workType,
        commitmentLevel,
        deadline,
        industry,
      } = req.body;

      if (!ObjectId.isValid(targetId)) {
        return res
          .status(400)
          .json({ success: false, error: "Malformed ID schema." });
      }

      const filter = { _id: new ObjectId(targetId), founderId: req.user.id };
      const updatePayload = {
        $set: {
          roleTitle,
          requiredSkills,
          workType,
          commitmentLevel,
          deadline: new Date(deadline),
          industry: industry || "General",
          updatedAt: new Date(),
        },
      };

      const updateResult = await opportunitiesCollection.updateOne(
        filter,
        updatePayload,
      );

      if (updateResult.matchedCount === 0) {
        return res.status(404).json({
          success: false,
          error: "Opportunity not located or unauthorized update attempt.",
        });
      }

      const freshDocument = await opportunitiesCollection.findOne({
        _id: new ObjectId(targetId),
      });
      res.status(200).json({
        success: true,
        message: "Records successfully updated.",
        data: freshDocument,
      });
    } catch (error) {
      console.error("DB Update Opportunity Exception:", error);
      res.status(500).json({
        success: false,
        error: "Internal server error modifying record target values.",
      });
    }
  },
);

// Drop Opportunity from active lists and database index pools
app.delete(
  "/api/opportunities/:id",
  requireAuth,
  requireRole("Founder"),
  async (req, res) => {
    try {
      const opportunitiesCollection =
        req.app.locals.opportunities || db.collection("opportunities");
      const targetId = req.params.id;

      if (!ObjectId.isValid(targetId)) {
        return res
          .status(400)
          .json({ success: false, error: "Malformed ID schema." });
      }

      const result = await opportunitiesCollection.deleteOne({
        _id: new ObjectId(targetId),
        founderId: req.user.id,
      });

      if (result.deletedCount === 0) {
        return res.status(404).json({
          success: false,
          error:
            "Opportunity record not located or unauthorized deletion attempt.",
        });
      }

      res.status(200).json({
        success: true,
        message: "Opportunity dropped from server index logs cleanly.",
      });
    } catch (error) {
      console.error("DB Deletion Opportunity Exception:", error);
      res.status(500).json({
        success: false,
        error:
          "Internal server error handling document dropping execution pipelines.",
      });
    }
  },
);

// =============================================
// --- APPLICATIONS PIPELINE FLOW MODULE ---
// =============================================

// Dispatch New Application to a specific Opportunity
app.post(
  "/api/applications",
  requireAuth,
  requireRole("Collaborator"),
  async (req, res) => {
    try {
      const {
        opportunityId,
        applicantEmail,
        portfolioLink,
        motivationMessage,
      } = req.body;

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
        return res
          .status(400)
          .json({ success: false, error: "Invalid opportunity ID" });
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

// List Submissions filtered cleanly by User Account Role Type parameters
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

// --- Server Lifecycle Connection Handlers ---
async function startServer() {
  try {
    console.log("Connecting to MongoDB Atlas Cluster...");
    await client.connect();
    await client.db("admin").command({ ping: 1 });

    db = client.db(dbName);

    // --- BIND CORE DATA COLLECTIONS DIRECTLY INTO APP LOCALS INSTANCES ---
    app.locals.db = db;
    app.locals.startups = db.collection("startups");
    app.locals.opportunities = db.collection("opportunities");

    console.log(`✓ Connected to Database: ${dbName}`);
    console.log(
      "✓ Successfully mapped active collections pointers to app.locals framework.",
    );

    app.listen(port, () => {
      console.log(`✓ Express server listening on network port: ${port}`);
    });
  } catch (error) {
    console.error(
      "✕ Critical error initializing database routing processes:",
      error,
    );
    process.exit(1);
  }
}

startServer();

process.on("SIGINT", async () => {
  await client.close();
  console.log(
    "\nMongoDB interface pipeline closed down cleanly. Server thread terminating.",
  );
  process.exit(0);
});
