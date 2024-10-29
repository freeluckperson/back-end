const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const morgan = require("morgan");
const cookieParser = require("cookie-parser"); // Importa cookie-parser

// Configuración de variables
const PORT = 4000;
const MONGO_URL =
  "mongodb+srv://productor:12345@agrovepaldb.bnumsj0.mongodb.net/";
const JWT_SECRET = "tu_secreto_jwt";

// Configuración de Express
const app = express();
app.use(express.json());
app.use(
  cors({
    // origin: "http://localhost:3000", // Ajusta el origen permitido
    origin: true,
    credentials: true, // Permitir cookies en solicitudes cross-origin
  })
);
app.use(morgan("dev"));
app.use(cookieParser()); // Usa cookie-parser

// Conexión a MongoDB y levantamiento del servidor
(async function initializeServer() {
  try {
    await mongoose.connect(MONGO_URL);
    console.log("Conectado a MongoDB");

    app.listen(PORT, () => {
      console.log(`Servidor corriendo en http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error("Error al conectar a MongoDB:", error);
    process.exit(1);
  }
})();

// Definición de esquema y modelo de usuario
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  username: { type: String, required: true },
  password: { type: String, required: true },
});
const User = mongoose.model("User", userSchema);

// Endpoint para registro
app.post("/register", async (req, res) => {
  try {
    const { email, username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({ email, username, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: "Usuario registrado exitosamente" });
  } catch (err) {
    res
      .status(500)
      .json({ message: "Error en el registro", error: err.message });
  }
});

// Endpoint para login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: "Credenciales incorrectas" });
    }

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, {
      expiresIn: "1h",
    });

    // Envía el token en una cookie HTTP-only
    res
      .cookie("token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production", // Solo en HTTPS en producción
        maxAge: 3600000, // 1 hora
      })
      .json({ message: "Login exitoso" });
  } catch (err) {
    res.status(500).json({ message: "Error en el login", error: err.message });
  }
});

// Middleware para verificar JWT desde la cookie
const authenticateToken = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ message: "Token requerido" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Token no válido" });
    req.user = user;
    next();
  });
};

// Ejemplo de endpoint protegido
app.get("/protected", authenticateToken, (req, res) => {
  res.json({ message: "Acceso a ruta protegida", userId: req.user.userId });
});

// Endpoint para logout
app.post("/logout", (req, res) => {
  res
    .clearCookie("token")
    .json({ message: "Logout exitoso, el token ha sido eliminado" });
});
