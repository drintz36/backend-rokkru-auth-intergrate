import jwt from "jsonwebtoken";

export const generateAccessToken = (userId) => {
    return jwt.sign(
        {user_id: userId},
        process.env.JWT_SECRET,
        {
            expiresIn: "2h",
        }
    );
};
export const generateRefreshToken = (userId) => {
    return jwt.sign(
        {user_id: userId},
        process.env.JWT_REFRESH_SECRET,
        {
            expiresIn: "7d",
        }
    );
};
