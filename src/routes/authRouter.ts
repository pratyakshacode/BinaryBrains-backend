import { Router } from "express";
import { googleAuthLogin, loginWithEmailAndPassword, logoutUser, signUpWithEmailAndPassword } from "../controllers/authController";

const authRouter = Router();

authRouter.post('/google', googleAuthLogin);
authRouter.post('/signup', signUpWithEmailAndPassword);
authRouter.post('/login', loginWithEmailAndPassword);
authRouter.post('/logout', logoutUser);

export default authRouter;