import bcrypt from "bcrypt";
import crypto from "crypto";
import jwt from "jsonwebtoken";

// const secret = crypto.randomBytes(32).toString("hex");
// console.log(secret)

const playload = { userId: "89jkjk390", email: "test@gmail.com" }
const token = jwt.sign(playload, process.env.JWT_SECRET_KEY);
console.log(token);

const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
console.log(decoded);

// const password = "katze1";

// const hashedPassword = await bcrypt.hash(password, 10);

// console.log(hashedPassword);

// const passwordCorrect = await bcrypt.compare("katze1", hashedPassword);

// console.log(passwordCorrect);
