import { cookieOptions } from "../../utils/auth/auth.js";
import OTP from "../../models/otpModel.js";
import User from "../../models/userModel.js";
import bcrypt from "bcryptjs/dist/bcrypt.js";
import UserSession from "../../models/userSessionModel.js";
import {
  generateAccessToken,
  generateRefreshToken,
} from "../../utils/auth/accessRefreshToken.js";

export const verifyOTP = async (req, res) => {
  try {
    const { email, otp } = req.body;

    // finduser

    const user = await User.findOne({
      where: { email },
    });

    // check user
    if (!user) {
      return res.status(400).json({
        message: "User not found",
      });
    }

    // find otp
    const validOTP = await OTP.findOne({
      where: {
        code: otp,
        user_id: user.user_id,
      },
    });

    if (!validOTP) {
      return res.status(400).json({
        message: "Invalid OTP",
      });
    }

    // expired date
    if (validOTP.expiresAt < new Date()) {
      return res.status(400).json({
        message: "OTP expired",
      });
    }

    // delete OTP after success

    await validOTP.destroy();

    // generate access token

    const accessToken = generateAccessToken(user.user_id);

    // generate refresh token

    const refreshToken = generateRefreshToken(user.user_id);

    // hash refresh token

    const refreshTokenHash = await bcrypt.hash(refreshToken, 10);

    // create session
    await UserSession.create({
      user_id: user.user_id,
      refresh_token_hash: refreshTokenHash,
      device_info: req.headers["user-agent"],
      ip_address: req.ip,
      expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      is_revoked: false,
    });

    //   store cookie
    res.cookie("refreshToken", refreshToken, cookieOptions);

    res.json({
      message: "login success",
      accessToken,
      user: {
        id: user.user_id,
        email: user.email,
        user_type: user.user_type_id,
      },
    });
  } catch (error) {
    return res.status(500).json({
      message: error.message,
    });
  }
};
