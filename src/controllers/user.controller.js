import { User } from "../models/user.model.js";
import {ApiError} from "../utils/ApiError.js";
import {asyncHandler} from "../utils/asyncHandler.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken"
import nodemailer from "nodemailer"

const transporter = nodemailer.createTransport({
  service: 'gmail',
  host: "smtp.gmail.com",
  port: 587,
  secure: false, 
  auth: {
    user: process.env.EMAIL_USER, 
    pass: process.env.APP_PASS, 
  },
});

const sendOtp = asyncHandler(async (req, res) => {
        try {
            const { email, password } = req.body;
            if (!(email && password)) {throw new ApiError(400,"All Fields are Required")};
            
              const existingUser = await User.findOne({ email: email });
              if (existingUser) {throw new ApiError(400,"User Already Registered")}
          
              const otp = Math.floor(1000 + Math.random() * 9000); // Generate 6-digit OTP
          
              const token = jwt.sign({ email: email,password: password, otp: otp }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "5m" });
          
              // Send OTP Email
              const response = await transporter.sendMail({
                from: process.env.EMAIL,
                to: email,
                subject: "Your OTP Code",
                text: `Your OTP is: ${otp}`,
              });
          
              if (!response) {throw new ApiError(500,'Error sending email')};
        
              res.status(200)
              .cookie("otp_token", token, { httpOnly: true, maxAge: 300000 })
              .json(
                new ApiResponse(
                    200,
                    {},
                    "OTP Sent Successfully"
                    )
                );
        } catch (error) {
            console.log(error);
        }
  });
  
 const verifyOtp = asyncHandler(async (req, res) => {
    const { otp } = req.body;
    if (!otp) {throw new ApiError(400, "OTP is Required")};

    const otpToken = req.cookies.otp_token;
    if (!otpToken) {throw new ApiError(400,"OTP Expired or Invalid")}
  
    let decoded;
        try {
            decoded = jwt.verify(otpToken, process.env.ACCESS_TOKEN_SECRET);
        } catch (error) {
            throw new ApiError(400,'OTP is Expired');
        }
      if (decoded.otp !== parseInt(otp)) {throw new ApiError(400,"Incorrect OTP")}
  
    //   Create JWT for email confirmation
      const authToken = jwt.sign({ email: decoded.email, password: decoded.password }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "10m" });
    //   res.cookie("auth_token", authToken, { httpOnly: true, maxAge: 600000 });
  
      res.status(200)
      .cookie("auth_token", authToken, { httpOnly: true, maxAge: 600000 })
      .json(
        new ApiResponse(
            200, {},
            "OTP verified"
        )
      )
  });

const userRegister = asyncHandler(async (req, res) => {
            const { fullName , phoneNumber } = req.body;
            // console.log(req.body);
            // console.log({fullName, phoneNumber});
            if (!(phoneNumber && fullName)) {throw new ApiError(400,"All Fields are Required")};
    
            const authToken = req.cookies.auth_token;
            if (!authToken) {throw new ApiError(400,"Unauthorized Access")};
        
            let decoded;
              try {
                 decoded = jwt.verify(authToken, process.env.ACCESS_TOKEN_SECRET);
              } catch (error) {
                throw new ApiError(400,'Session Expired');
              }
        
              const user = await User.create({
                email: decoded.email,
                password: decoded.password,
                fullName: fullName,
                phoneNumber: phoneNumber,
            })
        
            const createdUser = await User.findById(user._id).select("-password -refreshToken");
        
            if (!createdUser) {throw new ApiError(500,"Something went wrong while registering user")};
        
            res.status(200)
            .clearCookie("otp_token")
            .clearCookie("auth_token")
            .json(
                new ApiResponse(
                    200, createdUser,
                    "Successfully Registered"
                )
            )
  });

export {
    sendOtp,
    verifyOtp,
    userRegister
}