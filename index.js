const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");

dotenv.config();

const app = express();

const JWT_SECRET =
  process.env.JWT_SECRET || "digixvalley-admin-secret-key-2026";
const ADMIN_EMAIL =
  process.env.ADMIN_EMAIL || "sabadigixvalley@gmail.com";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "12345678";
const MONGODB_URI = process.env.MONGODB_URI;

// Middleware
app.use(cors());
app.use(express.json());

if (!MONGODB_URI) {
  console.error("MONGODB_URI environment variable is required!");
  process.exit(1);
}

// MongoDB Connection
mongoose
  .connect(MONGODB_URI, {
    serverSelectionTimeoutMS: 10000,
  })
  .then(() => console.log("MongoDB Connected Successfully"))
  .catch((err) => {
    console.error("MongoDB Connection Error:", err);
    process.exit(1);
  });

const ensureDbConnected = (req, res, next) => {
  if (mongoose.connection.readyState !== 1) {
    return res.status(503).json({
      message: "Database not connected. Please try again in a moment.",
    });
  }
  next();
};

// Registration Schema
const registrationSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  gender: { type: String, required: true },
  address: { type: String, required: true },
  programName: { type: String, required: true },
  projectName: { type: String, required: true },
  phone: { type: String, required: true },
  email: { type: String, required: true },
  submittedAt: { type: Date, default: Date.now },
});

const Registration = mongoose.model("Registration", registrationSchema);

// JWT Auth Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Access denied. Please login." });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid or expired token." });
    }
    req.user = user;
    next();
  });
};

// API Routes

// Admin Login
app.post("/api/admin/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Email and password are required!" });
    }

    if (email !== ADMIN_EMAIL) {
      return res.status(401).json({ message: "Invalid email or password!" });
    }

    const isPasswordValid = password === ADMIN_PASSWORD;
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid email or password!" });
    }

    const token = jwt.sign(
      { email, role: "admin" },
      JWT_SECRET,
      { expiresIn: "24h" },
    );

    res.status(200).json({
      success: true,
      message: "Login successful!",
      token,
      admin: { email },
    });
  } catch (error) {
    console.error("Login Error:", error);
    res.status(500).json({ message: "Server error. Please try again." });
  }
});

// Submit Registration
app.post("/api/register", ensureDbConnected, async (req, res) => {
  try {
    const {
      fullName,
      gender,
      address,
      programName,
      projectName,
      phone,
      email,
    } = req.body;

    // Validation
    if (
      !fullName ||
      !gender ||
      !address ||
      !programName ||
      !projectName ||
      !phone ||
      !email
    ) {
      return res.status(400).json({ message: "All fields are required!" });
    }

    // Check if email already exists
    const existingEmail = await Registration.findOne({ email });
    if (existingEmail) {
      return res.status(400).json({ message: "Email already registered!" });
    }

    // Create new registration
    const newRegistration = new Registration({
      fullName,
      gender,
      address,
      programName,
      projectName,
      phone,
      email,
    });

    await newRegistration.save();

    res.status(201).json({
      success: true,
      message: "Registration successful!",
      data: newRegistration,
    });
  } catch (error) {
    console.error("Registration Error:", error);
    res.status(500).json({ message: "Server error. Please try again." });
  }
});

// Get All Registrations (Admin - Protected)
app.get("/api/registrations", authenticateToken, ensureDbConnected, async (req, res) => {
  try {
    const registrations = await Registration.find().sort({ submittedAt: -1 });
    res.status(200).json({
      success: true,
      count: registrations.length,
      data: registrations,
    });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

// Get Single Registration (Admin - Protected)
app.get("/api/registrations/:id", authenticateToken, ensureDbConnected, async (req, res) => {
  try {
    const registration = await Registration.findById(req.params.id);
    if (!registration) {
      return res.status(404).json({ message: "Registration not found" });
    }
    res.status(200).json({ success: true, data: registration });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

// Delete Registration (Admin - Protected)
app.delete("/api/registrations/:id", authenticateToken, ensureDbConnected, async (req, res) => {
  try {
    const registration = await Registration.findByIdAndDelete(req.params.id);
    if (!registration) {
      return res.status(404).json({ message: "Registration not found" });
    }
    res.status(200).json({
      success: true,
      message: "Registration deleted successfully!",
    });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

// Health Check
app.get("/api/health", (req, res) => {
  const dbConnected = mongoose.connection.readyState === 1;
  res.status(dbConnected ? 200 : 503).json({
    status: dbConnected ? "OK" : "ERROR",
    message: dbConnected ? "Server is running!" : "Database not connected",
    database: dbConnected ? "connected" : "disconnected",
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
