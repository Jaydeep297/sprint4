import jwt from "jsonwebtoken";
import { User } from "../models/user.model.js";
import { ENV_VARS } from "../config/envVars.js";

export const protectRoute = async (req, res, next) => {
  try {
    // Extract the token from cookies
    const token = req.cookies["jwt-netflix"];

    if (!token) {
      console.log("No token provided in cookies");
      return res
        .status(401)
        .json({ success: false, message: "Unauthorized - No Token Provided" });
    }

    // Verify the token
    let decoded;
    try {
      decoded = jwt.verify(token, ENV_VARS.JWT_SECRET);
    } catch (error) {
      console.log("Token verification failed:", error.message);
      return res
        .status(401)
        .json({ success: false, message: "Unauthorized - Invalid Token" });
    }

    // Check if the user exists
    const user = await User.findById(decoded.userId).select("-password");
    if (!user) {
      console.log("User not found for token:", decoded.userId);
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    // Attach user to the request
    req.user = user;
    next();
  } catch (error) {
    console.log("Error in protectRoute middleware: ", error.message);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
};
