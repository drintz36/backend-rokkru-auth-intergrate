import User from "../../../models/userModel.js";
import {
  generateAccessToken,
  generateRefreshToken,
} from "../../../utils/auth/accessRefreshToken.js";
import bcrypt from "bcryptjs";
import { cookieOptions } from "../../../utils/auth/auth.js";

export const refreshToken = async (req, res) => {
  try {
    const userId = req.userId;      // from refresh middleware
    const session = req.session;    // from refresh middleware

    const user = await User.findByPk(userId);

    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    // ROTATE tokens
    const newAccessToken = generateAccessToken(userId);
    const newRefreshToken = generateRefreshToken(userId);

    const hashed = await bcrypt.hash(newRefreshToken, 10);

    // update session
    session.refresh_token_hash = hashed;
    await session.save();

    // set cookie
    res.cookie("refreshToken", newRefreshToken, cookieOptions);

    return res.json({
      accessToken: newAccessToken,
    });
  } catch (error) {
    return res.status(500).json({
      message: error.message,
    });
  }
};