import { Router } from "express";
import {
    sendOtp,
    verifyOtp,
    userRegister
} from "../controllers/user.controller.js";

const router = Router();
router.route("/send-otp").post(sendOtp);
router.route("/verify-otp").post(verifyOtp);
router.route("/register").post(userRegister);

export default router;