  // A middleware that has been created for authentication for the protected route so that
  // only those can post who is authenticated

  // const response=await fetch(`http://localhost:3000/api/books`,{
  //     method:"POST",
  //     body:JSON.stringify({
  //         title,
  //         caption
  //     }),
  //     headers:{Authorization:`Bearer ${token}`},
  // });


  // import jwt from "jsonwebtoken";
  // import User from "../models/User.js"

  // const protectRoute=async(req,res,next)=>{
  //     try {
  //         //get token
  //         const token=req.headers("Authorization").replace("Bearer ","");
  //         if(!token) return res.status(401).json({message:"No authentication taken, access denied"});
  //         //verify token
  //         const decoded=jwt.verify(token,process.env.JWT_SECRET);
  //         //find user
  //         //-password: means we select every field except the password
  //         const user=await User.findById(decoded.userId).select("-password");
  //         if(!user) return res.status(401).json({message:"Token is not valid"});

  //         req.user=user;
  //         next();
  //     } catch (error) {
  //         console.error("Authentication error",error.message);
  //         res.status(401).json({message:"Token is not valid"});
  //     }
  // };
  // export default protectRoute;


 import jwt from "jsonwebtoken";
import User from "../models/User.js";

const protectRoute = async (req, res, next) => {
  try {
    // 1. Get Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ message: "No authorization header" });
    }

    // 2. Check "Bearer" format
    if (!authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Invalid token format" });
    }

    // 3. Extract token
    const token = authHeader.split(" ")[1];
    if (!token) {
      return res.status(401).json({ message: "No token provided" });
    }

    // 4. Verify JWT
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // ─────────── New: Log token expiration ───────────
    // decoded.exp is in seconds since epoch
    console.log("Token expires at:", new Date(decoded.exp * 1000));

    // 5. Find user in DB
    console.log("Decoded token payload:", decoded);
    const user = await User.findById(decoded.userId).select("-password");
    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }

    // 6. Attach user and continue
    req.user = user;
    next();

  } catch (error) {
    console.error("Authentication Error:", error.message);

    // Specific JWT errors
    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ message: "Invalid token" });
    }
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({ message: "Token expired" });
    }

    // Generic fallback
    res.status(500).json({
      message: "Authentication failed",
      error: error.message
    });
  }
};

export default protectRoute;
