require("dotenv").config();

console.log("\n=== 🔍 BACKEND ENV SANITY DIAGNOSIS ===");
console.log("Terminal Execution Path (CWD):", process.cwd());
console.log(
  "Is STRIPE_SECRET_KEY visible?:",
  process.env.STRIPE_SECRET_KEY ? "YES ✅" : "NO ❌ (Missing/Undefined)",
);
if (process.env.STRIPE_SECRET_KEY) {
  console.log(
    "Key starting characters check:",
    process.env.STRIPE_SECRET_KEY.slice(0, 10) + "...",
  );
}
console.log("=========================================\n");

const jwt = require("jsonwebtoken");
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

// Global state caching container for Serverless instances
let cachedClient = null;
let cachedDb = null;
let db = null; // Left global to ensure seamless legacy route mapping

// 🎯 SERVERLESS DATABASE MANAGEMENT POOL
async function getDatabaseConnection() {
  if (cachedClient && cachedDb) {
    return cachedDb;
  }

  if (!uri) {
    throw new Error(
      "Critical Configuration Mismatch: MONGODB_URI is undefined.",
    );
  }

  const client = new MongoClient(uri, {
    serverApi: {
      version: ServerApiVersion.v1,
      strict: true,
      deprecationErrors: true,
    },
    // 🛡️ Safeguards to guarantee execution lifecycle breaks cleanly on connection failure
    connectTimeoutMS: 10000,
    socketTimeoutMS: 45000,
  });

  await client.connect();
  const connectedDb = client.db(dbName);

  // Cache link across warm container lifecycles
  cachedClient = client;
  cachedDb = connectedDb;

  return connectedDb;
}

// CORS configuration supporting dynamic credential passing
app.use(
  cors({
    origin: process.env.CORS_ORIGIN || clientUrl,
    credentials: true,
  }),
);
app.use(express.json());

// ⚡ THE MAGIC SERVERLESS INTERCEPTOR MIDDLEWARE
// Evaluates connection status on every execution thread automatically
app.use(async (req, res, next) => {
  try {
    const activeDb = await getDatabaseConnection();

    // Bind operational contexts to global state and locals
    db = activeDb;
    req.app.locals.db = activeDb;
    req.app.locals.startups = activeDb.collection("startups");
    req.app.locals.opportunities = activeDb.collection("opportunities");

    next();
  } catch (error) {
    console.error("✕ Database Pipeline Connection Failure Intercepted:", error);
    res.status(500).json({
      success: false,
      error:
        "Database handshake timeout. Please check your network cluster or retry.",
    });
  }
});

// =================================================================
// CHAPTER 1: AUTHENTICATION & MIDDLEWARE
// =================================================================

// --- BETTER AUTH TO JWT BRIDGE MODULE ---
app.post("/api/auth/sync-token", async (req, res) => {
  try {
    let token = req.body?.token;

    if (token) {
      jwt.verify(token, process.env.JWT_SECRET);
    } else {
      // Fallback: validate Better Auth session via Next.js
      const cookieHeader = req.headers.cookie || "";
      const match = cookieHeader.match(/better-auth\.session_token=([^;]+)/);
      const betterAuthToken = match ? match[1] : null;

      if (!betterAuthToken) {
        return res.status(401).json({
          success: false,
          error: "Better Auth session cookie missing.",
        });
      }

      const sessionCheck = await fetch(`${clientUrl}/api/auth/get-session`, {
        headers: { Cookie: `better-auth.session_token=${betterAuthToken}` },
      });

      if (!sessionCheck.ok) {
        return res.status(401).json({
          success: false,
          error: "Failed to verify Better Auth session.",
        });
      }

      const sessionData = await sessionCheck.json();
      const user = sessionData.user;

      if (!user) {
        return res
          .status(401)
          .json({ success: false, error: "No user mapped to this session." });
      }

      const jwtPayload = {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role || "Collaborator",
      };

      token = jwt.sign(jwtPayload, process.env.JWT_SECRET, { expiresIn: "7d" });
    }

    res.cookie("startupforge_jwt", token, {
      httpOnly: true,
      secure: true, // 🎯 FORCED TRUE: Required by browsers for cross-site tracking
      sameSite: "none", // 🎯 CHANGED TO NONE: Allows the cookie to jump from frontend Vercel to backend Vercel
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: "/",
    });

    res.json({ success: true, message: "JWT synchronized successfully." });
  } catch (error) {
    console.error("JWT Sync Bridge Error:", error);
    res.status(500).json({ success: false, error: "Internal sync failure." });
  }
});

// --- Stateless JWT Verification Middleware ---
function requireAuth(req, res, next) {
  try {
    const cookieHeader = req.headers.cookie;
    if (!cookieHeader) {
      return res
        .status(401)
        .json({ success: false, error: "Unauthorized: Missing credentials" });
    }

    const match = cookieHeader.match(/startupforge_jwt=([^;]+)/);
    const token = match ? match[1] : null;

    if (!token) {
      return res
        .status(401)
        .json({ success: false, error: "Unauthorized: Access token missing" });
    }

    const decodedPayload = jwt.verify(token, process.env.JWT_SECRET);

    req.user = {
      id: decodedPayload.id,
      email: decodedPayload.email,
      name: decodedPayload.name,
      role: decodedPayload.role,
    };

    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      error: "Unauthorized: Session token invalid or expired",
    });
  }
}

// Stateful Role Verification Middleware
const requireRole = (...requiredRoles) => {
  return async (req, res, next) => {
    try {
      if (!req.user || !req.user.id) {
        return res
          .status(401)
          .json({ success: false, error: "Unauthorized request." });
      }

      const currentDb = req.app.locals.db || db;
      const userId = req.user.id;
      const userEmail = req.user.email;

      const queryConditions = [{ _id: userId }, { id: userId }];
      if (ObjectId.isValid(userId)) {
        queryConditions.push({ _id: new ObjectId(userId) });
      }
      if (userEmail) {
        queryConditions.push({ email: userEmail });
      }

      let liveUser = await currentDb
        .collection("user")
        .findOne({ $or: queryConditions });
      if (!liveUser) {
        liveUser = await currentDb
          .collection("users")
          .findOne({ $or: queryConditions });
      }

      if (!liveUser) {
        return res.status(401).json({
          success: false,
          error: "User session exists but database record is missing.",
        });
      }

      const liveRole = liveUser.role || "Collaborator";
      const normalizedRoles = requiredRoles.map((r) => r.toLowerCase());

      if (
        !normalizedRoles.includes(liveRole.toLowerCase()) &&
        liveRole.toLowerCase() !== "admin"
      ) {
        console.error(
          `[AUTH BLOCK] User ${userEmail} tried to access restricted route as ${liveRole}.`,
        );
        return res.status(403).json({
          success: false,
          error: `Access Denied. This action requires elevated privileges.`,
        });
      }

      req.user.role = liveRole;
      next();
    } catch (error) {
      console.error("Role Verification Middleware Error:", error);
      res.status(500).json({
        success: false,
        error: "Server error verifying security clearance.",
      });
    }
  };
};

// =================================================================
// CHAPTER 2: PUBLIC & UTILITY ROUTES
// =================================================================

app.get("/", (req, res) => {
  res.json({ message: "StartupForge API is running" });
});

// Secure Image Upload Route (ImgBB Bridge)
app.post("/api/images", upload.single("image"), async (req, res) => {
  try {
    if (!req.file)
      return res
        .status(400)
        .json({ success: false, error: "No image file provided" });

    const imgbbKey = process.env.IMGBB_API_KEY;
    if (!imgbbKey)
      return res.status(500).json({
        success: false,
        error: "Server config missing: ImgBB API key.",
      });

    const blob = new Blob([req.file.buffer], { type: req.file.mimetype });
    const formData = new FormData();
    formData.append("image", blob, req.file.originalname);

    const imgbbRes = await fetch(
      `https://api.imgbb.com/1/upload?key=${imgbbKey}`,
      { method: "POST", body: formData },
    );
    const data = await imgbbRes.json();

    if (!data.success)
      return res.status(400).json({
        success: false,
        error: "Image upload rejected by hosting provider.",
      });

    res.json({
      success: true,
      data: { url: data.data.url, display_url: data.data.display_url },
    });
  } catch (error) {
    res
      .status(500)
      .json({ success: false, error: `Internal error: ${error.message}` });
  }
});

app.patch("/api/users/role", requireAuth, async (req, res) => {
  try {
    const { role } = req.body;
    const currentDb = req.app.locals.db || db;
    const userId = req.user.id;
    const userEmail = req.user.email;

    console.log(
      `[AUTH-SYNC] Attempting to upgrade user ${userEmail} to ${role}...`,
    );

    const queryConditions = [{ _id: userId }, { id: userId }];
    if (ObjectId.isValid(userId))
      queryConditions.push({ _id: new ObjectId(userId) });
    if (userEmail) queryConditions.push({ email: userEmail });

    const query = { $or: queryConditions };

    let result = await currentDb
      .collection("user")
      .updateOne(query, { $set: { role: role, updatedAt: new Date() } });
    if (result.matchedCount === 0) {
      result = await currentDb
        .collection("users")
        .updateOne(query, { $set: { role: role, updatedAt: new Date() } });
    }

    if (result.matchedCount === 0) {
      return res
        .status(400)
        .json({ success: false, error: "User not found in database." });
    }

    res.json({
      success: true,
      message: `Account successfully upgraded to ${role}`,
    });
  } catch (error) {
    res.status(500).json({ success: false, error: "Database sync failed." });
  }
});

// 🛒 Generate Stripe Checkout Session
app.post("/api/checkout", requireAuth, async (req, res) => {
  try {
    const { plan, price, role } = req.body;

    // Ensure you have STRIPE_SECRET_KEY in your Vercel Environment Variables!
    const secretKey = process.env.STRIPE_SECRET_KEY;
    const stripeInstance = require("stripe")(secretKey);

    // Create the Stripe Checkout session
    const session = await stripeInstance.checkout.sessions.create({
      payment_method_types: ["card"],
      customer_email: req.user.email, // Grabbed from your requireAuth middleware
      line_items: [
        {
          price_data: {
            currency: "usd",
            product_data: {
              name: `StartupForge ${plan || "Pro"} Plan`,
              description: `Upgrade your account to the ${plan || "Pro"} tier.`,
            },
            unit_amount: price ? price * 100 : 9900, // Price in cents (e.g., 9900 = $99.00)
          },
          quantity: 1,
        },
      ],
      mode: "payment",
      metadata: {
        userId: req.user.id,
        role: role || req.user.role,
      },
      // 🎯 Redirects user back to your LIVE frontend after payment
      success_url: `https://startupforge-client-kappa.vercel.app/payment-success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `https://startupforge-client-kappa.vercel.app/pricing`,
    });

    // Send the Stripe URL back to the frontend so it can redirect the user
    res.json({ success: true, url: session.url });
  } catch (error) {
    console.error("Stripe Checkout Error:", error);
    res
      .status(500)
      .json({ success: false, error: "Failed to initialize payment gateway." });
  }
});

// Stripe Success Fulfillment Webhook
app.post("/api/checkout/success", async (req, res) => {
  try {
    const { sessionId } = req.body;
    if (!sessionId)
      return res
        .status(400)
        .json({ success: false, error: "Missing session token." });

    const secretKey = process.env.STRIPE_SECRET_KEY;
    const stripeInstance = require("stripe")(secretKey);
    const stripeSession =
      await stripeInstance.checkout.sessions.retrieve(sessionId);

    if (!stripeSession || stripeSession.payment_status !== "paid") {
      return res
        .status(400)
        .json({ success: false, error: "Transaction invalid." });
    }

    const userRole = stripeSession.metadata?.role || "collaborator";
    const customerEmail = stripeSession.customer_details?.email;
    const capitalVolume = stripeSession.amount_total / 100;
    const currentDb = req.app.locals.db || db;

    const customerAccount = await currentDb
      .collection("user")
      .findOne({ email: customerEmail });
    if (!customerAccount)
      return res.status(404).json({
        success: false,
        error: "Fulfillment Error: No user account found.",
      });

    const transactionLogged = await currentDb
      .collection("payments")
      .findOne({ stripeSessionId: sessionId });
    if (transactionLogged) {
      return res.json({
        success: true,
        message: "Fulfillment previously completed.",
        role: userRole,
      });
    }

    await currentDb.collection("payments").insertOne({
      stripeSessionId: sessionId,
      userId: customerAccount._id,
      userEmail: customerEmail,
      userName: customerAccount.name,
      amountPaid: capitalVolume,
      currency: stripeSession.currency?.toUpperCase() || "USD",
      dateSettled: new Date(),
    });

    await currentDb.collection("transactions").insertOne({
      stripeSessionId: sessionId,
      userEmail: customerEmail,
      userName: customerAccount.name,
      amount: capitalVolume,
      status: "Succeeded",
      date: new Date(),
    });

    await currentDb
      .collection("user")
      .updateOne(
        { _id: customerAccount._id },
        { $set: { plan: "Pro", updatedAt: new Date() } },
      );

    return res.json({
      success: true,
      message: "Transaction saved and plan elevated.",
      role: userRole,
    });
  } catch (error) {
    return res
      .status(500)
      .json({ success: false, error: `Execution Error: ${error.message}` });
  }
});

// Public Endpoint: Fetch All Registered Startups
app.get("/api/startups", async (req, res) => {
  try {
    const startupsCollection =
      req.app.locals.startups || db.collection("startups");
    const startups = await startupsCollection
      .find({ isApproved: true })
      .sort({ createdAt: -1 })
      .toArray();

    res.json({ success: true, data: startups });
  } catch (error) {
    res.status(500).json({ success: false, error: "Failed to fetch startups" });
  }
});

// Public Endpoint: Search Opportunities
app.get("/api/opportunities", async (req, res) => {
  try {
    const opportunitiesCollection = db.collection("opportunities");
    const {
      page = 1,
      limit = 9,
      startupId,
      search,
      workType,
      industry,
    } = req.query;
    const pageNum = parseInt(page);
    const limitNum = parseInt(limit);

    let query = {};
    if (startupId) query.startupId = startupId;

    if (search) {
      query.$or = [
        { roleTitle: { $regex: search, $options: "i" } },
        { requiredSkills: { $regex: search, $options: "i" } },
      ];
    }

    if (workType) {
      const workTypesArray = workType.split(",").map((type) => type.trim());
      query.workType = { $in: workTypesArray };
    }

    if (industry) {
      const industryArray = industry.split(",").map((ind) => ind.trim());
      query.industry = { $in: industryArray };
    }

    const totalCount = await opportunitiesCollection.countDocuments(query);
    const opportunities = await opportunitiesCollection
      .find(query)
      .sort({ createdAt: -1 })
      .skip((pageNum - 1) * limitNum)
      .limit(limitNum)
      .toArray();

    res.json({
      success: true,
      data: opportunities,
      pagination: {
        total: totalCount,
        page: pageNum,
        limit: limitNum,
        totalPages: Math.ceil(totalCount / limitNum),
      },
    });
  } catch (error) {
    res
      .status(500)
      .json({ success: false, error: "Server error fetching opportunities." });
  }
});

app.get("/api/opportunities/:id", async (req, res) => {
  try {
    const opportunitiesCollection =
      req.app.locals.opportunities || db.collection("opportunities");
    const targetId = req.params.id;

    const matchConditions = [targetId];
    if (ObjectId.isValid(targetId))
      matchConditions.push(new ObjectId(targetId));

    const opportunity = await opportunitiesCollection.findOne({
      _id: { $in: matchConditions },
    });
    if (!opportunity)
      return res
        .status(404)
        .json({ success: false, error: "Opportunity not found" });

    res.json({ success: true, data: opportunity });
  } catch (error) {
    res
      .status(500)
      .json({ success: false, error: "Failed to fetch opportunity" });
  }
});

// =================================================================
// CHAPTER 3: COLLABORATOR ROUTES
// =================================================================

app.get("/api/collaborator/profile", requireAuth, async (req, res) => {
  try {
    const usersCollection = db.collection("user");
    const targetId = req.user.id;

    const queryConditions = [targetId];
    if (ObjectId.isValid(targetId))
      queryConditions.push(new ObjectId(targetId));

    const activeUser = await usersCollection.findOne({
      _id: { $in: queryConditions },
    });
    if (!activeUser)
      return res
        .status(404)
        .json({ success: false, error: "Identity profile not found." });

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
    res
      .status(500)
      .json({ success: false, error: "Internal registry reading fault." });
  }
});

app.put("/api/collaborator/profile", requireAuth, async (req, res) => {
  try {
    const usersCollection = db.collection("user");
    const targetId = req.user.id;
    const { name, image, bio, skills } = req.body;

    const queryConditions = [targetId];
    if (ObjectId.isValid(targetId))
      queryConditions.push(new ObjectId(targetId));

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

    if (result.matchedCount === 0)
      return res
        .status(404)
        .json({ success: false, error: "User mapping missing." });

    res.json({ success: true, message: "Profile updated successfully." });
  } catch (error) {
    res
      .status(500)
      .json({ success: false, error: "Internal update pipeline failed." });
  }
});

app.get("/api/collaborator/overview", requireAuth, async (req, res) => {
  try {
    const applicationsCollection = db.collection("applications");
    const activeUser = await db
      .collection("user")
      .findOne({ email: req.user.email });
    const userPlan = activeUser?.plan || "Free";

    const queryConditions = [req.user.id];
    if (ObjectId.isValid(req.user.id))
      queryConditions.push(new ObjectId(req.user.id));

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
    res
      .status(500)
      .json({ success: false, error: "Analytics pipeline failed." });
  }
});

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
        return res
          .status(400)
          .json({ success: false, error: "All fields are required" });
      }

      const queryConditions = [req.user.id];
      if (ObjectId.isValid(req.user.id))
        queryConditions.push(new ObjectId(req.user.id));

      const activeUser = await db
        .collection("user")
        .findOne({ _id: { $in: queryConditions } });
      const allowedCeiling = activeUser?.plan === "Pro" ? 100 : 3;

      const totalApplicationsSubmitted = await db
        .collection("applications")
        .countDocuments({ applicantId: { $in: queryConditions } });
      if (totalApplicationsSubmitted >= allowedCeiling) {
        return res
          .status(403)
          .json({ success: false, error: `Quota Exhausted. Upgrade to Pro.` });
      }

      const opportunity = await db.collection("opportunities").findOne({
        _id: ObjectId.isValid(opportunityId)
          ? new ObjectId(opportunityId)
          : opportunityId,
      });
      if (!opportunity)
        return res
          .status(404)
          .json({ success: false, error: "Opportunity not found" });

      const existing = await db
        .collection("applications")
        .findOne({ opportunityId, applicantId: req.user.id });
      if (existing)
        return res
          .status(409)
          .json({ success: false, error: "Already applied" });

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
    res
      .status(500)
      .json({ success: false, error: "Failed to fetch applications" });
  }
});

// =================================================================
// CHAPTER 4: FOUNDER ROUTES
// =================================================================

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
        status: "Pending",
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const result = await startupsCollection.insertOne(startup);
      res
        .status(201)
        .json({ success: true, data: { ...startup, _id: result.insertedId } });
    } catch (error) {
      res
        .status(500)
        .json({ success: false, error: "Failed to create startup" });
    }
  },
);

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
      res
        .status(500)
        .json({ success: false, error: "Failed to fetch startup data." });
    }
  },
);

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

      if (!ObjectId.isValid(startupId))
        return res
          .status(400)
          .json({ success: false, error: "Invalid target ID." });

      const updateResult = await startupsCollection.updateOne(
        { _id: new ObjectId(startupId), founderId: req.user.id },
        {
          $set: {
            startupName,
            logo,
            industry,
            description,
            fundingStage,
            founderEmail,
            updatedAt: new Date(),
          },
        },
      );

      if (updateResult.matchedCount === 0)
        return res
          .status(404)
          .json({ success: false, error: "Not found or unauthorized." });

      const freshDocument = await startupsCollection.findOne({
        _id: new ObjectId(startupId),
      });
      res.status(200).json({ success: true, data: freshDocument });
    } catch (error) {
      res
        .status(500)
        .json({ success: false, error: "Internal server update failed." });
    }
  },
);

app.delete(
  "/api/startups/:id",
  requireAuth,
  requireRole("Founder"),
  async (req, res) => {
    try {
      const startupsCollection =
        req.app.locals.startups || db.collection("startups");
      const startupId = req.params.id;

      if (!ObjectId.isValid(startupId))
        return res
          .status(400)
          .json({ success: false, error: "Invalid target ID." });

      const result = await startupsCollection.deleteOne({
        _id: new ObjectId(startupId),
        founderId: req.user.id,
      });
      if (result.deletedCount === 0)
        return res
          .status(404)
          .json({ success: false, error: "Not found or unauthorized." });

      res.status(200).json({ success: true, message: "Startup removed." });
    } catch (error) {
      res.status(500).json({ success: false, error: "Deletion failed." });
    }
  },
);

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
      const usersCollection = db.collection("user");

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
        return res
          .status(400)
          .json({ success: false, error: "All fields are required." });
      }

      const activeUser = await usersCollection.findOne({
        email: req.user.email,
      });
      const allowedCeiling = activeUser?.plan === "Pro" ? 200 : 10;

      const founderQueryConditions = [req.user.id];
      if (ObjectId.isValid(req.user.id))
        founderQueryConditions.push(new ObjectId(req.user.id));

      const totalPostedOpportunities =
        await opportunitiesCollection.countDocuments({
          founderId: { $in: founderQueryConditions },
        });
      if (totalPostedOpportunities >= allowedCeiling) {
        return res.status(403).json({
          success: false,
          error: `Quota Breached. Upgrade to Pro to post more.`,
        });
      }

      const startup = await startupsCollection.findOne({
        _id: ObjectId.isValid(startupId) ? new ObjectId(startupId) : startupId,
        founderId: { $in: founderQueryConditions },
      });

      if (!startup)
        return res.status(403).json({
          success: false,
          error: "Access Denied to this corporate profile.",
        });

      if (startup.isApproved !== true) {
        return res.status(403).json({
          success: false,
          error:
            "Action Denied: Your startup is still pending Admin approval. You can only post opportunities for verified startups.",
        });
      }

      const opportunity = {
        startupId: startup._id,
        startupName: startup.startupName,
        stripeSessionId: null,
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
        data: { ...opportunity, _id: result.insertedId },
      });
    } catch (error) {
      res
        .status(500)
        .json({ success: false, error: "Failed to post opportunity." });
    }
  },
);

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

      if (!ObjectId.isValid(targetId))
        return res
          .status(400)
          .json({ success: false, error: "Malformed ID schema." });

      const updateResult = await opportunitiesCollection.updateOne(
        { _id: new ObjectId(targetId), founderId: req.user.id },
        {
          $set: {
            roleTitle,
            requiredSkills,
            workType,
            commitmentLevel,
            deadline: new Date(deadline),
            industry: industry || "General",
            updatedAt: new Date(),
          },
        },
      );

      if (updateResult.matchedCount === 0)
        return res
          .status(404)
          .json({ success: false, error: "Not located or unauthorized." });

      const freshDocument = await opportunitiesCollection.findOne({
        _id: new ObjectId(targetId),
      });
      res.status(200).json({ success: true, data: freshDocument });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: "Internal server error modifying record.",
      });
    }
  },
);

app.delete(
  "/api/opportunities/:id",
  requireAuth,
  requireRole("Founder"),
  async (req, res) => {
    try {
      const opportunitiesCollection =
        req.app.locals.opportunities || db.collection("opportunities");
      const targetId = req.params.id;

      if (!ObjectId.isValid(targetId))
        return res
          .status(400)
          .json({ success: false, error: "Malformed ID schema." });

      const result = await opportunitiesCollection.deleteOne({
        _id: new ObjectId(targetId),
        founderId: req.user.id,
      });
      if (result.deletedCount === 0)
        return res
          .status(404)
          .json({ success: false, error: "Not located or unauthorized." });

      res.status(200).json({ success: true, message: "Opportunity dropped." });
    } catch (error) {
      res
        .status(500)
        .json({ success: false, error: "Deletion pipeline failed." });
    }
  },
);

app.patch(
  "/api/applications/:id/status",
  requireAuth,
  requireRole("Founder"),
  async (req, res) => {
    try {
      const applicationsCollection = db.collection("applications");
      const applicationId = req.params.id;
      const { status } = req.body;

      if (!["Accepted", "Rejected"].includes(status))
        return res
          .status(400)
          .json({ success: false, error: "Invalid status." });

      const application = await applicationsCollection.findOne({
        _id: ObjectId.isValid(applicationId)
          ? new ObjectId(applicationId)
          : applicationId,
      });
      if (!application)
        return res
          .status(404)
          .json({ success: false, error: "Application not found." });

      const opportunity = await db.collection("opportunities").findOne({
        _id: ObjectId.isValid(application.opportunityId)
          ? new ObjectId(application.opportunityId)
          : application.opportunityId,
        founderId: req.user.id,
      });

      if (!opportunity)
        return res
          .status(403)
          .json({ success: false, error: "Access denied." });

      await applicationsCollection.updateOne(
        { _id: application._id },
        { $set: { status, updatedAt: new Date() } },
      );
      res.json({ success: true, message: `Application updated to ${status}.` });
    } catch (error) {
      res
        .status(500)
        .json({ success: false, error: "Internal error altering status." });
    }
  },
);

app.get(
  "/api/founder/overview",
  requireAuth,
  requireRole("Founder"),
  async (req, res) => {
    try {
      const opportunitiesCollection = db.collection("opportunities");
      const applicationsCollection = db.collection("applications");
      const activeUser = await db
        .collection("user")
        .findOne({ email: req.user.email });
      const userPlan = activeUser?.plan || "Free";

      const founderQueryConditions = [req.user.id];
      if (ObjectId.isValid(req.user.id))
        founderQueryConditions.push(new ObjectId(req.user.id));

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
          plan: userPlan,
        },
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: "Internal error resolving dashboard data.",
      });
    }
  },
);

// =================================================================
// CHAPTER 5: ADMIN ROUTES
// =================================================================

app.get(
  "/api/admin/overview",
  requireAuth,
  requireRole("admin"),
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

      res.json({
        success: true,
        data: {
          totalUsers,
          totalStartups,
          totalOpportunities,
          totalRevenue: financialAggregation[0]?.revenueTotal || 0,
        },
      });
    } catch (error) {
      res
        .status(500)
        .json({ success: false, error: "System failed to resolve overview." });
    }
  },
);

app.get(
  "/api/admin/users",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const operationalUsersList = await db
        .collection("user")
        .find({ email: { $ne: "admin@startupforge.com" } })
        .sort({ createdAt: -1 })
        .toArray();
      res.json({ success: true, data: operationalUsersList });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: "Failed to read system accounts list.",
      });
    }
  },
);

app.patch(
  "/api/admin/users/:id/toggle-block",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const targetUserId = req.params.id;
      const { isBlocked } = req.body;

      const queryConditions = [targetUserId];
      if (ObjectId.isValid(targetUserId))
        queryConditions.push(new ObjectId(targetUserId));

      const matchUser = await db
        .collection("user")
        .findOne({ _id: { $in: queryConditions } });
      if (!matchUser)
        return res
          .status(404)
          .json({ success: false, error: "Record missing." });

      await db
        .collection("user")
        .updateOne(
          { _id: matchUser._id },
          { $set: { isBlocked: !!isBlocked, updatedAt: new Date() } },
        );
      res.json({
        success: true,
        message: `Access processing state updated successfully.`,
      });
    } catch (error) {
      res
        .status(500)
        .json({ success: false, error: "Failed to write modifications." });
    }
  },
);

app.get(
  "/api/admin/startups",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const currentDb = req.app.locals.db || db;
      const ecosystemStartupsDeck = await currentDb
        .collection("startups")
        .find({})
        .sort({ createdAt: -1 })
        .toArray();
      res.json({ success: true, data: ecosystemStartupsDeck });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: "Failed to map active startups entries.",
      });
    }
  },
);

app.patch(
  "/api/admin/startups/:id/approve",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const currentDb = req.app.locals.db || db;
      const targetId = req.params.id;
      const { isApproved } = req.body;

      const conditions = [targetId];
      if (ObjectId.isValid(targetId)) conditions.push(new ObjectId(targetId));

      const patchAction = await currentDb.collection("startups").updateOne(
        { _id: { $in: conditions } },
        {
          $set: {
            isApproved: !!isApproved,
            status: isApproved ? "Approved" : "Pending",
            updatedAt: new Date(),
          },
        },
      );

      if (patchAction.matchedCount === 0)
        return res.status(404).json({
          success: false,
          error: "Venture identity asset not matching.",
        });
      res.json({
        success: true,
        message: "Verification parameters committed.",
      });
    } catch (error) {
      res
        .status(500)
        .json({ success: false, error: "Failed to authorize status changes." });
    }
  },
);

app.delete(
  "/api/admin/startups/:id",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const currentDb = req.app.locals.db || db;
      const targetId = req.params.id;

      const matchConditions = [targetId];
      if (ObjectId.isValid(targetId))
        matchConditions.push(new ObjectId(targetId));

      const deletionReport = await currentDb
        .collection("startups")
        .deleteOne({ _id: { $in: matchConditions } });
      if (deletionReport.deletedCount === 0)
        return res
          .status(404)
          .json({ success: false, error: "Target entry not found." });

      res.json({
        success: true,
        message: "Profile context permanently removed.",
      });
    } catch (error) {
      res
        .status(500)
        .json({ success: false, error: "Cleanup process aborted." });
    }
  },
);

app.get(
  "/api/admin/transactions",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const systemFinancialHistory = await db
        .collection("transactions")
        .find({})
        .sort({ date: -1 })
        .toArray();
      res.json({ success: true, data: systemFinancialHistory });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: "Failed to extract transaction history.",
      });
    }
  },
);

// =================================================================
// CHAPTER 6: SYSTEM LIFECYCLE & CATCH-ALL
// =================================================================

app.use((req, res) => {
  console.log(`\n⚠️ [404 CATCH-ALL] Unhandled request intercepted!`);
  console.log(`Method: ${req.method} | URL: ${req.url}`);
  res.status(404).json({
    success: false,
    error: `Route ${req.method} ${req.url} does not exist.`,
  });
});

// Local Dev Standalone Boot Sequence (Only runs if NOT on production Vercel serverless containers)
if (process.env.NODE_ENV !== "production") {
  app.listen(port, () => {
    console.log(
      `✓ Express server listening on local development network port: ${port}`,
    );
  });
}

// 🚨 CRUCIAL: Export the fully modified Express app instance for the Vercel compilation layer
module.exports = app;
