import express from "express";
import { PORT, JWT_SECRET, MONGO_URL } from "./config.js";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";
import morgan from "morgan";
import cookieParser from "cookie-parser";
import { z } from "zod";

const app = express();
app.use(express.json());
app.use(cors({ origin: true, credentials: true }));
app.use(morgan("dev"));
app.use(cookieParser());

// MongoDB connection and server initialization
(async function initializeServer() {
  try {
    await mongoose.connect(MONGO_URL);
    console.log("Connected to MongoDB");
    app.listen(PORT, () =>
      console.log(`Server running at http://localhost:${PORT}`)
    );
  } catch (error) {
    console.error("Error connecting to MongoDB:", error);
    process.exit(1);
  }
})();

// User schema and model definition
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  username: { type: String, required: true },
  password: { type: String, required: true },
  isDeleted: { type: Boolean, default: false },
  isAdmin: { type: Boolean, default: false }, // Admin flag
  notifications: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Notification",
    },
  ],
});
const User = mongoose.model("User", userSchema);

// Notification schema and model definition
const notificationSchema = new mongoose.Schema({
  message: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  recipients: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }], // Cambiado a array de destinatarios
});
const Notification = mongoose.model("Notification", notificationSchema);

// Define validation schemas with Zod
const registerSchema = z.object({
  email: z.string().email("Invalid email format"),
  username: z.string().min(3, "Username must be at least 3 characters long"),
  password: z.string().min(6, "Password must be at least 6 characters long"),
});
const loginSchema = z.object({
  email: z.string().email("Invalid email format"),
  password: z.string().min(6, "Password must be at least 6 characters long"),
});

// Validation middleware
const validate = (schema) => (req, res, next) => {
  try {
    schema.parse(req.body);
    next();
  } catch (err) {
    const errorDetails = err.errors[0].message;
    res.status(400).json({ message: "Invalid data", errors: errorDetails });
  }
};

// Registration endpoint
app.post("/register", validate(registerSchema), async (req, res) => {
  try {
    const { email, username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ email, username, password: hashedPassword });
    await newUser.save();
    res.status(201).json({ message: "User successfully registered" });
  } catch (err) {
    res.status(500).json({ message: "Registration error", error: err.message });
  }
});

// Login endpoint
app.post("/login", validate(loginSchema), async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email, isDeleted: false });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: "Invalid credentials" });
    }
    const token = jwt.sign(
      { userId: user._id, isAdmin: user.isAdmin },
      JWT_SECRET,
      { expiresIn: "1h" }
    );
    res
      .cookie("token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        maxAge: 3600000,
      })
      .json({
        message: "Login successful",
        id: user._id,
        isAdmin: user.isAdmin,
      });
  } catch (err) {
    res.status(500).json({ message: "Login error", error: err.message });
  }
});

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ message: "Token required" });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
};

// Endpoint to create a notification for multiple users (Admin only)
app.post("/notifications", authenticateToken, async (req, res) => {
  if (!req.user.isAdmin)
    return res.status(403).json({ message: "Admin privileges required" });
  const { message, recipientIds } = req.body; // Cambiado para aceptar multiples destinatarios

  const notification = new Notification({
    message,
    recipients: recipientIds, // Cambiado para asignar multiples destinatarios
  });
  await notification.save();

  await User.updateMany(
    { _id: { $in: recipientIds } }, // Actualizar todos los usuarios especificados
    { $push: { notifications: notification._id } }
  );

  res.status(201).json({ message: "Notification sent to multiple users" });
}); // Actualización para múltiples destinatarios

// Endpoint to view user's own notifications
app.get("/my-notifications", authenticateToken, async (req, res) => {
  const user = await User.findById(req.user.userId).populate("notifications");
  res.json(user.notifications);
});

// Endpoint for admin to grant admin privileges to other users
app.put("/grant-admin/:id", authenticateToken, async (req, res) => {
  if (!req.user.isAdmin)
    return res.status(403).json({ message: "Admin privileges required" });
  const { id } = req.params;
  await User.findByIdAndUpdate(id, { isAdmin: true });
  res.json({ message: "User granted admin privileges" });
});

// Logical delete endpoint for users
app.delete("/users/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const user = await User.findByIdAndUpdate(
      id,
      { isDeleted: true },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json({ message: "User deleted", user });
  } catch (err) {
    res
      .status(500)
      .json({ message: "Error deleting user", error: err.message });
  }
});

// Example protected endpoint
app.get("/protected", authenticateToken, (req, res) => {
  res.json({ message: "Access to protected route", userId: req.user.userId });
});

// Logout endpoint
app.post("/logout", (_, res) => {
  res
    .clearCookie("token")
    .json({ message: "Logout successful, token removed" });
});
