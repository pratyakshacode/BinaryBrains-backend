import { Router } from "express";
import { googleAuthLogin, loginWithEmailAndPassword, signUpWithEmailAndPassword } from "../controllers/authController";

const authRouter = Router();

authRouter.post('/google', googleAuthLogin);
authRouter.post('/signup', signUpWithEmailAndPassword);
authRouter.post('/login', loginWithEmailAndPassword);

export default authRouter;