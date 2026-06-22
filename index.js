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

    // --- ADMINISTRATIVE PRIVILEGE INJECT SECURITY INTERCEPT ---
    if (req.user?.email === "admin@startupforge.com") {
      req.user.role = "Admin";
    }

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
        isApproved: false,
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
// --- MARKET OPPORTUNITIES MANAGEMENT MODULE ---
// =============================================

// Post New Position Opportunity
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
        return res.status(400).json({
          success: false,
          error: "Malformed Startup ID alignment schema.",
        });
      }

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

      const opportunity = {
        startupId: new ObjectId(startupId),
        startupName: startup.startupName,
        startupLogo: startup.logo,
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
      res.status(500).json({
        success: false,
        error: "Failed to link and create opportunity.",
      });
    }
  },
);

// Fetch Opportunities List (With Type-Agnostic Query Filters)
app.get("/api/opportunities", async (req, res) => {
  try {
    const opportunitiesCollection =
      req.app.locals.opportunities || db.collection("opportunities");
    const { startupId, page, limit } = req.query;

    let query = {};
    if (startupId) {
      const matchConditions = [startupId];
      if (ObjectId.isValid(startupId)) {
        matchConditions.push(new ObjectId(startupId));
      }
      query.startupId = { $in: matchConditions };
    }

    if (startupId) {
      const listings = await opportunitiesCollection
        .find(query)
        .sort({ createdAt: -1 })
        .toArray();

      return res.status(200).json({ success: true, data: listings });
    }

    const pageNum = parseInt(page, 10) || 1;
    const limitNum = parseInt(limit, 10) || 6;
    const skip = (pageNum - 1) * limitNum;

    const [totalDocuments, listings] = await Promise.all([
      opportunitiesCollection.countDocuments(query),
      opportunitiesCollection
        .find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limitNum)
        .toArray(),
    ]);

    res.status(200).json({
      success: true,
      data: listings,
      pagination: {
        total: totalDocuments,
        page: pageNum,
        limit: limitNum,
        totalPages: Math.ceil(totalDocuments / limitNum),
      },
    });
  } catch (error) {
    console.error("DB Fetch Opportunities Pagination/Filter Exception:", error);
    res.status(500).json({
      success: false,
      error: "Internal server error sorting positions collection.",
    });
  }
});

// Lookup Singular Specific Opportunity Details
app.get("/api/opportunities/:id", async (req, res) => {
  try {
    const opportunitiesCollection =
      req.app.locals.opportunities || db.collection("opportunities");
    const targetId = req.params.id;

    const matchConditions = [targetId];
    if (ObjectId.isValid(targetId)) {
      matchConditions.push(new ObjectId(targetId));
    }

    const opportunity = await opportunitiesCollection.findOne({
      _id: { $in: matchConditions },
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

// Drop Opportunity from active lists
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

// Application Submission Pathway
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

      const matchConditions = [opportunityId];
      if (ObjectId.isValid(opportunityId)) {
        matchConditions.push(new ObjectId(opportunityId));
      }

      const opportunity = await db.collection("opportunities").findOne({
        _id: { $in: matchConditions },
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

// List Submissions filtered cleanly by Account Role Parameters
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

// FOUNDER ACCEPT/REJECT SYSTEM MANAGEMENT ROUTE
app.patch(
  "/api/applications/:id/status",
  requireAuth,
  requireRole("Founder"),
  async (req, res) => {
    try {
      const applicationsCollection = db.collection("applications");
      const applicationId = req.params.id;
      const { status } = req.body;

      if (!["Accepted", "Rejected"].includes(status)) {
        return res
          .status(400)
          .json({ success: false, error: "Invalid status value assignment." });
      }

      const matchConditions = [applicationId];
      if (ObjectId.isValid(applicationId)) {
        matchConditions.push(new ObjectId(applicationId));
      }

      const application = await applicationsCollection.findOne({
        _id: { $in: matchConditions },
      });
      if (!application) {
        return res.status(404).json({
          success: false,
          error: "Application profile registry not found.",
        });
      }

      const opportunityMatchConditions = [application.opportunityId];
      if (ObjectId.isValid(application.opportunityId)) {
        opportunityMatchConditions.push(
          new ObjectId(application.opportunityId),
        );
      }

      const opportunity = await db.collection("opportunities").findOne({
        _id: { $in: opportunityMatchConditions },
        founderId: req.user.id,
      });

      if (!opportunity) {
        return res.status(403).json({
          success: false,
          error: "Forbidden: Access denied to change this document state.",
        });
      }

      await applicationsCollection.updateOne(
        { _id: application._id },
        { $set: { status, updatedAt: new Date() } },
      );

      res.json({
        success: true,
        message: `Application status updated to ${status} successfully.`,
      });
    } catch (error) {
      console.error("Application processing toggle exception:", error);
      res.status(500).json({
        success: false,
        error: "Internal server error altering status state.",
      });
    }
  },
);

// =================================================================
// --- COLLABORATOR DATA PERSISTENCE PROFILE INSTANCES ---
// =================================================================

// GET: Fetch Active Collaborator Profile Specifications
app.get("/api/collaborator/profile", requireAuth, async (req, res) => {
  try {
    const usersCollection = db.collection("user");
    const targetId = req.user.id;

    const queryConditions = [targetId];
    if (ObjectId.isValid(targetId)) {
      queryConditions.push(new ObjectId(targetId));
    }

    const activeUser = await usersCollection.findOne({
      _id: { $in: queryConditions },
    });

    if (!activeUser) {
      console.warn(
        `[PROFILE GET 404] No user document matched ID: "${targetId}"`,
      );
      return res
        .status(404)
        .json({ success: false, error: "Identity records profile not found." });
    }

    res.json({
      success: true,
      data: {
        name: activeUser.name,
        email: activeUser.email,
        image: activeUser.image,
        bio: activeUser.bio || "",
        skills: activeUser.skills || [],
      },
    });
  } catch (error) {
    console.error("Fetch profile configuration mapping exception:", error);
    res
      .status(500)
      .json({ success: false, error: "Internal registry reading fault." });
  }
});

// PUT: Modify/Synchronize Extended Collaborator Profile Values
app.put("/api/collaborator/profile", requireAuth, async (req, res) => {
  try {
    console.log("\n--- [PROFILE PUT INTAKE] ---");
    console.log("Target User ID:", req.user?.id);

    const usersCollection = db.collection("user");
    const targetId = req.user.id;
    const { name, image, bio, skills } = req.body;

    const queryConditions = [targetId];
    if (ObjectId.isValid(targetId)) {
      queryConditions.push(new ObjectId(targetId));
    }

    const result = await usersCollection.updateOne(
      { _id: { $in: queryConditions } },
      {
        $set: {
          name,
          image,
          bio: bio || "",
          skills: Array.isArray(skills) ? skills : [],
          updatedAt: new Date(),
        },
      },
    );

    console.log("[DB RESULT] Metrics returned:", {
      matchedCount: result.matchedCount,
      modifiedCount: result.modifiedCount,
    });

    if (result.matchedCount === 0) {
      return res.status(404).json({
        success: false,
        error: "User collection profile mapping index missing.",
      });
    }

    res.json({
      success: true,
      message: "Profile dataset values updated successfully.",
    });
  } catch (error) {
    console.error("\n✕ !!! CRITICAL UPDATE PIPELINE EXCEPTION !!! ✕");
    res.status(500).json({
      success: false,
      error: "Internal update engine processing pipeline failed.",
    });
  }
});

// =================================================================
// --- COLLABORATOR TELEMETRY DASHBOARD METRICS ---
// =================================================================

// GET: Fetch Dynamic Collaborator Dashboard Counter Metrics
app.get("/api/collaborator/overview", requireAuth, async (req, res) => {
  try {
    const applicationsCollection = db.collection("applications");
    const targetId = req.user.id;

    const queryConditions = [targetId];
    if (ObjectId.isValid(targetId)) {
      queryConditions.push(new ObjectId(targetId));
    }

    const [totalApplied, totalAccepted, totalPending] = await Promise.all([
      applicationsCollection.countDocuments({
        applicantId: { $in: queryConditions },
      }),
      applicationsCollection.countDocuments({
        applicantId: { $in: queryConditions },
        status: "Accepted",
      }),
      applicationsCollection.countDocuments({
        applicantId: { $in: queryConditions },
        status: "Pending",
      }),
    ]);

    console.log(`\n--- [COLLABORATOR OVERVIEW TELEMETRY] ---`);
    console.log(
      `User: ${req.user.email} | Applied: ${totalApplied} | Accepted: ${totalAccepted} | Pending: ${totalPending}`,
    );

    res.json({
      success: true,
      data: {
        totalApplied,
        totalAccepted,
        totalPending,
      },
    });
  } catch (error) {
    console.error("Collaborator overview metrics compilation failure:", error);
    res.status(500).json({
      success: false,
      error: "Internal analytics pipeline processing failed.",
    });
  }
});

// =================================================================
// --- WORKSPACE FULFILLMENT & TELEMETRY DECKS ---
// =================================================================

// GET: Fetch Dynamic Collaborator Dashboard Counter Metrics
app.get("/api/collaborator/overview", requireAuth, async (req, res) => {
  try {
    const applicationsCollection = db.collection("applications");
    const usersCollection = db.collection("user");
    const targetId = req.user.id;

    const queryConditions = [targetId];
    if (ObjectId.isValid(targetId)) {
      queryConditions.push(new ObjectId(targetId));
    }

    const activeUser = await usersCollection.findOne({
      _id: { $in: queryConditions },
    });
    const userPlan = activeUser?.plan || "Free";

    const [totalApplied, totalAccepted, totalPending] = await Promise.all([
      applicationsCollection.countDocuments({
        applicantId: { $in: queryConditions },
      }),
      applicationsCollection.countDocuments({
        applicantId: { $in: queryConditions },
        status: "Accepted",
      }),
      applicationsCollection.countDocuments({
        applicantId: { $in: queryConditions },
        status: "Pending",
      }),
    ]);

    res.json({
      success: true,
      data: { totalApplied, totalAccepted, totalPending, plan: userPlan },
    });
  } catch (error) {
    console.error("Collaborator overview telemetry exception:", error);
    res.status(500).json({
      success: false,
      error: "Internal analytics pipeline processing failed.",
    });
  }
});

// POST: Stripe Success Transaction Capture & Record Fulfillment
// =================================================================
// --- STRIPE SUCCESS TRANSACTION CAPTURE & RECORD FULFILLMENT ---
// =================================================================
app.post("/api/checkout/success", async (req, res) => {
  try {
    const { sessionId } = req.body;
    if (!sessionId) {
      return res
        .status(400)
        .json({ success: false, error: "Missing session identifier token." });
    }

    // SAFE GUARD: Dynamically require and initialize Stripe if not defined globally
    const stripeInstance =
      typeof stripe !== "undefined"
        ? stripe
        : require("stripe")(process.env.STRIPE_SECRET_KEY);

    if (!process.env.STRIPE_SECRET_KEY) {
      return res.status(500).json({
        success: false,
        error:
          "Server Configuration Error: STRIPE_SECRET_KEY is missing from backend variables.",
      });
    }

    // Retrieve the checkout session from Stripe
    const stripeSession =
      await stripeInstance.checkout.sessions.retrieve(sessionId);
    if (!stripeSession || stripeSession.payment_status !== "paid") {
      return res.status(400).json({
        success: false,
        error: "Transaction mapping validation check rejected.",
      });
    }

    // SAFE GUARD: Ensure database pointers are fully available
    const currentDb = req.app.locals.db || db;
    if (!currentDb) {
      return res.status(500).json({
        success: false,
        error: "Server Lifecycle Error: Database connection is not ready yet.",
      });
    }

    const paymentsCollection = currentDb.collection("payments");
    const usersCollection = currentDb.collection("user");

    // Check if this transaction has already been fulfilled
    const transactionLogged = await paymentsCollection.findOne({
      stripeSessionId: sessionId,
    });
    if (transactionLogged) {
      return res.json({
        success: true,
        message: "Fulfillment completed during previous execution cycle.",
      });
    }

    const customerEmail = stripeSession.customer_details?.email;
    const capitalVolume = stripeSession.amount_total / 100;

    // Find the user associated with the payment email
    const customerAccount = await usersCollection.findOne({
      email: customerEmail,
    });
    if (!customerAccount) {
      return res.status(404).json({
        success: false,
        error: `Fulfillment Sync Error: No user account found matching checkout email "${customerEmail}".`,
      });
    }

    // Log transaction payload directly into payments collection
    await paymentsCollection.insertOne({
      stripeSessionId: sessionId,
      userId: customerAccount._id,
      userEmail: customerEmail,
      userName: customerAccount.name,
      amountPaid: capitalVolume,
      currency: stripeSession.currency?.toUpperCase() || "USD",
      dateSettled: new Date(),
    });

    // Elevate the user to the Pro Plan
    await usersCollection.updateOne(
      { _id: customerAccount._id },
      { $set: { plan: "Pro", updatedAt: new Date() } },
    );

    console.log(
      `\n✓ [STRIPE FULFILLMENT COMPLETED] Upgraded: ${customerEmail}`,
    );

    return res.json({
      success: true,
      message: "Transaction saved and plan elevated successfully.",
    });
  } catch (error) {
    console.error("Fulfillment intercept execution error loop pass:", error);

    // EXPOSE ERROR MESSAGE: Return the exact crash trace to pinpoint configuration errors instantly
    return res.status(500).json({
      success: false,
      error: `Internal Execution Error: ${error.message}`,
    });
  }
});

// GET: Founder Dashboard Insights Telemetry
app.get(
  "/api/founder/overview",
  requireAuth,
  requireRole("Founder"),
  async (req, res) => {
    try {
      const opportunitiesCollection = db.collection("opportunities");
      const applicationsCollection = db.collection("applications");
      const targetFounderId = req.user.id;

      const founderQueryConditions = [targetFounderId];
      if (ObjectId.isValid(targetFounderId)) {
        founderQueryConditions.push(new ObjectId(targetFounderId));
      }

      const myOpportunities = await opportunitiesCollection
        .find({ founderId: { $in: founderQueryConditions } })
        .project({ _id: 1 })
        .toArray();

      const opportunityIdsStrings = myOpportunities.map((opp) =>
        opp._id.toString(),
      );

      const recentApplications = await applicationsCollection
        .find({ opportunityId: { $in: opportunityIdsStrings } })
        .sort({ createdAt: -1 })
        .limit(4)
        .toArray();

      const [totalOpportunities, totalApplications, totalAccepted] =
        await Promise.all([
          opportunitiesCollection.countDocuments({
            founderId: { $in: founderQueryConditions },
          }),
          applicationsCollection.countDocuments({
            opportunityId: { $in: opportunityIdsStrings },
          }),
          applicationsCollection.countDocuments({
            opportunityId: { $in: opportunityIdsStrings },
            status: "Accepted",
          }),
        ]);

      res.json({
        success: true,
        data: {
          metrics: { totalOpportunities, totalApplications, totalAccepted },
          recentApplications,
        },
      });
    } catch (error) {
      console.error("Error compiling founder overview analytics:", error);
      res.status(500).json({
        success: false,
        error: "Internal server error resolving dashboard data summaries.",
      });
    }
  },
);

// =================================================================
// --- FOUNDER DASHBOARD TELEMETRY INSIGHTS PIPELINE ---
// =================================================================

app.get(
  "/api/founder/overview",
  requireAuth,
  requireRole("Founder"),
  async (req, res) => {
    try {
      const opportunitiesCollection = db.collection("opportunities");
      const applicationsCollection = db.collection("applications");
      const targetFounderId = req.user.id;

      const founderQueryConditions = [targetFounderId];
      if (ObjectId.isValid(targetFounderId)) {
        founderQueryConditions.push(new ObjectId(targetFounderId));
      }

      const myOpportunities = await opportunitiesCollection
        .find({ founderId: { $in: founderQueryConditions } })
        .project({ _id: 1 })
        .toArray();

      const opportunityIdsStrings = myOpportunities.map((opp) =>
        opp._id.toString(),
      );

      const recentApplications = await applicationsCollection
        .find({ opportunityId: { $in: opportunityIdsStrings } })
        .sort({ createdAt: -1 })
        .limit(4)
        .toArray();

      const [totalOpportunities, totalApplications, totalAccepted] =
        await Promise.all([
          opportunitiesCollection.countDocuments({
            founderId: { $in: founderQueryConditions },
          }),
          applicationsCollection.countDocuments({
            opportunityId: { $in: opportunityIdsStrings },
          }),
          applicationsCollection.countDocuments({
            opportunityId: { $in: opportunityIdsStrings },
            status: "Accepted",
          }),
        ]);

      console.log(`\n--- [FOUNDER METRICS CALCULATED ENGINE] ---`);
      console.log(
        `Founder: ${req.user.email} | Opps: ${totalOpportunities} | Apps: ${totalApplications}`,
      );

      res.json({
        success: true,
        data: {
          metrics: {
            totalOpportunities,
            totalApplications,
            totalAccepted,
          },
          recentApplications,
        },
      });
    } catch (error) {
      console.error(
        "Critical error compiling founder overview analytics metrics:",
        error,
      );
      res.status(500).json({
        success: false,
        error: "Internal server error resolving dashboard data summaries.",
      });
    }
  },
);

// =================================================================
// --- SYSTEM ADMIN MANAGEMENT INFRASTRUCTURE COMMAND DECKS ---
// =================================================================

// GET: Core Telemetry Analytical Overview Aggregator Deck
app.get(
  "/api/admin/overview",
  requireAuth,
  requireRole("Admin"),
  async (req, res) => {
    try {
      const totalUsers = await db
        .collection("user")
        .countDocuments({ email: { $ne: "admin@startupforge.com" } });
      const totalStartups = await db.collection("startups").countDocuments({});
      const totalOpportunities = await db
        .collection("opportunities")
        .countDocuments({});

      const financialAggregation = await db
        .collection("transactions")
        .aggregate([
          {
            $match: {
              status: { $in: ["Succeeded", "succeeded", "Paid", "paid"] },
            },
          },
          { $group: { _id: null, revenueTotal: { $sum: "$amount" } } },
        ])
        .toArray();

      const totalRevenue = financialAggregation[0]?.revenueTotal || 0;

      res.json({
        success: true,
        data: { totalUsers, totalStartups, totalOpportunities, totalRevenue },
      });
    } catch (error) {
      console.error("Overview aggregation mapping failure:", error);
      res.status(500).json({
        success: false,
        error:
          "System failed to resolve core overview records data components.",
      });
    }
  },
);

// GET: View All Registered User Accounts (Admin Curated Manifest View)
app.get(
  "/api/admin/users",
  requireAuth,
  requireRole("Admin"),
  async (req, res) => {
    try {
      const usersCollection = db.collection("user");
      const operationalUsersList = await usersCollection
        .find({ email: { $ne: "admin@startupforge.com" } })
        .sort({ createdAt: -1 })
        .toArray();

      res.json({ success: true, data: operationalUsersList });
    } catch (error) {
      console.error("Admin user indexing exception:", error);
      res.status(500).json({
        success: false,
        error: "Failed to read system accounts list.",
      });
    }
  },
);

// PATCH: Toggle Account Ban Processing Suspension Flags (Block/Unblock Operations)
app.patch(
  "/api/admin/users/:id/toggle-block",
  requireAuth,
  requireRole("Admin"),
  async (req, res) => {
    try {
      const usersCollection = db.collection("user");
      const targetUserId = req.params.id;
      const { isBlocked } = req.body;

      const queryConditions = [targetUserId];
      if (ObjectId.isValid(targetUserId)) {
        queryConditions.push(new ObjectId(targetUserId));
      }

      const matchUser = await usersCollection.findOne({
        _id: { $in: queryConditions },
      });
      if (!matchUser) {
        return res.status(404).json({
          success: false,
          error: "Target structural context operator record missing.",
        });
      }

      await usersCollection.updateOne(
        { _id: matchUser._id },
        { $set: { isBlocked: !!isBlocked, updatedAt: new Date() } },
      );

      res.json({
        success: true,
        message: `Access processing state updated successfully.`,
      });
    } catch (error) {
      console.error("Admin toggle user block exception:", error);
      res.status(500).json({
        success: false,
        error: "Failed to write modifications to account document state.",
      });
    }
  },
);

// GET: View All Startups across ecosystem clusters (Admin Auditing Matrix Desk)
app.get(
  "/api/admin/startups",
  requireAuth,
  requireRole("Admin"),
  async (req, res) => {
    try {
      const startupsCollection = db.collection("startups");
      const ecosystemStartupsDeck = await startupsCollection
        .find({})
        .sort({ createdAt: -1 })
        .toArray();
      res.json({ success: true, data: ecosystemStartupsDeck });
    } catch (error) {
      console.error("Admin read startups matrix error:", error);
      res.status(500).json({
        success: false,
        error: "Failed to map active startups entries.",
      });
    }
  },
);

// PATCH: Approve / Validate Startup Active Profile Visibility Field Listing
app.patch(
  "/api/admin/startups/:id/approve",
  requireAuth,
  requireRole("Admin"),
  async (req, res) => {
    try {
      const startupsCollection = db.collection("startups");
      const targetId = req.params.id;
      const { isApproved } = req.body;

      const conditions = [targetId];
      if (ObjectId.isValid(targetId)) {
        conditions.push(new ObjectId(targetId));
      }

      const patchAction = await startupsCollection.updateOne(
        { _id: { $in: conditions } },
        { $set: { isApproved: !!isApproved, updatedAt: new Date() } },
      );

      if (patchAction.matchedCount === 0) {
        return res.status(404).json({
          success: false,
          error: "Venture identity asset node not matching.",
        });
      }

      res.json({
        success: true,
        message:
          "Venture structural verification parameters committed successfully.",
      });
    } catch (error) {
      console.error("Admin verification toggle failure:", error);
      res.status(500).json({
        success: false,
        error:
          "Failed to authorize status value configuration modification changes.",
      });
    }
  },
);

// DELETE: Administrative Hard Eviction Removal of Fraudulent Startup Node Data Clusters
app.delete(
  "/api/admin/startups/:id",
  requireAuth,
  requireRole("Admin"),
  async (req, res) => {
    try {
      const startupsCollection = db.collection("startups");
      const targetId = req.params.id;

      const matchConditions = [targetId];
      if (ObjectId.isValid(targetId)) {
        matchConditions.push(new ObjectId(targetId));
      }

      const deletionReport = await startupsCollection.deleteOne({
        _id: { $in: matchConditions },
      });

      if (deletionReport.deletedCount === 0) {
        return res.status(404).json({
          success: false,
          error: "Venture target entry reference not found.",
        });
      }

      res.json({
        success: true,
        message:
          "Target profile node context permanently removed from active directories.",
      });
    } catch (error) {
      console.error("Admin hard delete startup failure:", error);
      res.status(500).json({
        success: false,
        error: "Forced database records cleanup process aborted.",
      });
    }
  },
);

// GET: Financial Accounting System Auditing Transcripts Log Sheet Ledger
app.get(
  "/api/admin/transactions",
  requireAuth,
  requireRole("Admin"),
  async (req, res) => {
    try {
      const systemFinancialHistory = await db
        .collection("transactions")
        .find({})
        .sort({ date: -1 })
        .toArray();

      res.json({ success: true, data: systemFinancialHistory });
    } catch (error) {
      console.error("Admin finance audit mapping error:", error);
      res.status(500).json({
        success: false,
        error: "Failed to extract core payment transaction documents history.",
      });
    }
  },
);

// Catch-all route to debug every single unhandled request hitting this port
app.use((req, res) => {
  console.log(`\n⚠️ [404 CATCH-ALL] Unhandled request intercepted!`);
  console.log(`Method: ${req.method}`);
  console.log(`Requested URL: ${req.url}`);
  console.log(`Headers Host: ${req.headers.host}`);

  res.status(404).json({
    success: false,
    error: `Route ${req.method} ${req.url} does not exist on this active process thread.`,
  });
});

async function startServer() {
  try {
    console.log("Connecting to MongoDB Atlas Cluster...");
    await client.connect();
    await client.db("admin").command({ ping: 1 });

    db = client.db(dbName);

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
