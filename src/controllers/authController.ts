import { Request, Response } from "express"
import { OAuth2Client } from "google-auth-library";
import userModel from "../models/user/user.model";
import { isInvalid } from "../utils/tools";
import { USER_ROLE, USER_ROLES_ARRAY } from "../utils/types";
import { HTTP_STATUS_CODE, HTTP_STATUS_MESSAGES } from "../utils/httpStatus";
import * as jwt from 'jsonwebtoken';
import logger from "../utils/logger";
import bcrypt from 'bcryptjs';

const googleClient = new OAuth2Client({ clientId: process.env.GOOGLE_CLIENT_ID, clientSecret: process.env.GOOGLE_CLIENT_SECRET });

export const signUpWithEmailAndPassword = async (req: Request, res: Response) : Promise<any> => {

    try {
        
        logger.info("Signing up the user with email and password");
        // find the params from req body
        const { email, password, userName, role, firstName, lastName } = req.body;

        if(
            isInvalid(email) || 
            isInvalid(password) || 
            isInvalid(userName) || 
            isInvalid(role) || 
            isInvalid(firstName) || 
            isInvalid(lastName) || 
            role === 'admin' ||
            !USER_ROLES_ARRAY.includes(role)
        ) {
            logger.error("Invalid/Missing fields found.")
            return res.status(HTTP_STATUS_CODE.BAD_REQUEST).json({ status: HTTP_STATUS_MESSAGES.BAD_REQUEST, message: "Invalid/Missing fields!" });
        } 

        logger.info("Finding the user with email.");
        // find the existing user from database
        const existingUser = await userModel.findOne({ email });

        if(!isInvalid(existingUser)) {

            // user found
            logger.info("User already exists with email.");

            if(!isInvalid(existingUser.googleId)){
                // if the user google id exists which means that user has already account and signed up with google
                logger.info("User has signed up with google previously.");
                return res.status(HTTP_STATUS_CODE.BAD_REQUEST).json(
                    { 
                        status: HTTP_STATUS_MESSAGES.BAD_REQUEST, 
                        message: "Please try login with google!"
                    }
                );
                
            } else {

                // user already has account with email and password
                return res.status(HTTP_STATUS_CODE.BAD_REQUEST).json({ 
                    status: HTTP_STATUS_MESSAGES.BAD_REQUEST, 
                    message: "User with email already exists!"
                })
            }
        }

        // create the hash of the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // create the new user with required data
        const newUser = await userModel.create({
            firstName, lastName, email, userName, role, password: hashedPassword
        })

        // generate the accessToken and refreshToken for new user
        logger.info("User created. Generating the access and refresh token.");
        const { accessToken, refreshToken } = generateTokens(newUser._id.toString(), USER_ROLE.student);

        newUser.refreshToken = refreshToken;
        await newUser.save();

        // set the cookies for the user
        res.cookie("jwtToken", 
            accessToken, 
            { 
                maxAge: 7 * 24 * 60 * 60 * 1000,
                 httpOnly: true, 
                 secure: process.env.ENVIRONMENT === 'production', 
                 sameSite: 'lax' 
            }
        );

        res.cookie("refreshToken", 
            refreshToken, 
            { 
                maxAge: 7 * 24 * 60 * 60 * 1000, 
                httpOnly: true, 
                secure: process.env.ENVIRONMENT === 'production', 
                sameSite: 'lax' 
            }
        );

        return res.status(HTTP_STATUS_CODE.SUCCESS).json(
            { 
                status: HTTP_STATUS_MESSAGES.SUCCESS, 
                message: "User created!",
                data: {
                    firstName: newUser.firstName,
                    lastName: newUser.lastName,
                    email: newUser.email,
                    userName: newUser.userName,
                    refreshToken: refreshToken,
                    token: accessToken,
                    avatar: newUser.avatar, 
                    newComer: false
                }
            }
        )

    } catch (error) {
        
        logger.error(`Error in ${signUpWithEmailAndPassword.name}`, error.message || error);
        return res.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).json({ status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR, message: "Error creating user. Please try after some time.", error: error.message });

    }
}

export const loginWithEmailAndPassword = async (req: Request, res: Response) : Promise<any> => {
    try {

        // get the params from req body
        const { email, password } = req.body;

        // check if either email or password is not found
        if(isInvalid(email) || isInvalid(password)) {
            return res.status(HTTP_STATUS_CODE.BAD_REQUEST).json({ status: HTTP_STATUS_MESSAGES.BAD_REQUEST, message: 'Missing fields!' });
        }

        // find the existing user
        const existingUser = await userModel.findOne({ email });

        if(isInvalid(existingUser)) {
            // user does not exist
            return res.status(HTTP_STATUS_CODE.NOT_FOUND).json({ status: HTTP_STATUS_MESSAGES.NOT_FOUND, message: "Invalid credentials!" })
        }

        // compare the password given by user to the saved password
        const userPasswordMatch = await bcrypt.compare(password, existingUser.password);

        // if invalid userpassword then password does not match
        if(!userPasswordMatch) {
            return res.status(HTTP_STATUS_CODE.FORBIDDEN).json({ status: HTTP_STATUS_MESSAGES.FORBIDDEN, message: "Invalid credentials" })
        }

        // generate the accessToken and refreshToken for new user
        logger.info("User exists. Generating the access and refresh token.");
        const { accessToken, refreshToken } = generateTokens(existingUser._id.toString(), existingUser.role);
        existingUser.refreshToken = refreshToken;
        await existingUser.save();

        // set the cookies for the user
        res.cookie("jwtToken", accessToken, { maxAge: 7 * 24 * 60 * 60 * 1000, httpOnly: true, secure: process.env.ENVIRONMENT === 'production', sameSite: 'lax' });
        res.cookie("refreshToken", refreshToken, { maxAge: 7 * 24 * 60 * 60 * 1000, httpOnly: true, secure: process.env.ENVIRONMENT === 'production', sameSite: 'lax' });

        return res.status(HTTP_STATUS_CODE.SUCCESS).json({ 
            status: HTTP_STATUS_MESSAGES.SUCCESS,  
            data: {
                firstName: existingUser.firstName,
                lastName: existingUser.lastName,
                refreshToken: refreshToken,
                token: accessToken,
                email: existingUser.email,
                avatar: existingUser.avatar,
                newComer: false
            },
            message: "Login Successful!"
        });

    } catch (error) {

        logger.error(`Error in ${loginWithEmailAndPassword.name}`, error.message || error);
        return res.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).json({ status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR, message: "Error in logging in user. Please try after sometime.", error: error.message })
        
    }
}

export const googleAuthLogin = async (req: Request, res: Response): Promise<any> => {

    try {

        logger.info("Logging in user using google.");

        // get the token sent from frontend
        const { token } = req.body;
        
        logger.info("Authenticating the token with google.");

        // verify the token from the google
        let ticket: any;

        try {
            
            // validate the token here
            ticket = await googleClient.verifyIdToken({
                idToken: token,
                audience: process.env.GOOGLE_CLIENT_ID
            });

        } catch (error) {

            logger.error("Error in validating google token. Invalid google token found for authentication.")
            return res.status(HTTP_STATUS_CODE.BAD_GATEWAY).json({ status: HTTP_STATUS_MESSAGES.BAD_GATEWAY, message: "Invalid google auth token found." });
        }

        // get the data provided by the google
        const { sub, email, picture, given_name, family_name } = ticket.getPayload();
        logger.debug("Found user data from google", { sub, email, picture, given_name, family_name });

        // find the user from the database
        logger.info("Checking for the existing user.")
        const existingUser = await userModel.findOne({ googleId: sub });

        if(isInvalid(existingUser)) {

            logger.info("User not found. Creating new user.")
            
            const hashedPassword = await bcrypt.hash(process.env.USER_DEFAULT_PASSWORD, 10);
            const defaultUserName = await generateUniqueUsername(given_name, family_name || "");

            // create new user
            const newUser = await userModel.create({
                firstName: given_name,
                lastName: family_name || "",
                email: email,
                avatar: picture,
                role: USER_ROLE.student,
                userName: defaultUserName,
                password: hashedPassword,
                googleId: sub
            });

            // generate the accessToken and refreshToken for new user
            logger.info("User created. Generating the access and refresh token.");
            const { accessToken, refreshToken } = generateTokens(newUser._id.toString(), USER_ROLE.student);

            newUser.refreshToken = refreshToken;
            await newUser.save();

            // set the cookies for the user
            res.cookie("jwtToken", 
                accessToken, 
            { 
                maxAge: 7 * 24 * 60 * 60 * 1000, 
                httpOnly: true, 
                secure: process.env.ENVIRONMENT === 'production', 
                sameSite: 'lax' 
            });

            res.cookie("refreshToken", 
                refreshToken, 
                { 
                    maxAge: 7 * 24 * 60 * 60 * 1000, 
                    httpOnly: true, 
                    secure: process.env.ENVIRONMENT === 'production', 
                    sameSite: 'lax' 
                }
            );

            logger.info("Returning success response.")
            return res.status(HTTP_STATUS_CODE.SUCCESS)
                .json({ 
                    status: HTTP_STATUS_MESSAGES.SUCCESS, 
                    data: { 
                        firstName: given_name, 
                        lastName: family_name, 
                        avatar: picture, 
                        userName: newUser.userName,
                        newComer: true,
                        token: accessToken,
                        refreshToken: refreshToken,
                    } 
                });

        } else {

            logger.info("User already exists. Generating accessToken and refreshToken for user to send.");

            // if the user googleId not found then the user has signed in with email and password
            if(isInvalid(existingUser.googleId)) {
                logger.error("User does not have google id. Account was created with email and password. Returning Bad Request as resposne.");
                return res.status(HTTP_STATUS_CODE.BAD_REQUEST).json({ status: HTTP_STATUS_MESSAGES.BAD_REQUEST, message: "Please login using email and password!" })
            }

            // generate tokens for the user
            const { accessToken, refreshToken } = generateTokens(existingUser._id.toString(), existingUser.role)

            existingUser.refreshToken = refreshToken;
            await existingUser.save();

            // set the cookie
            res.cookie("jwtToken", 
                accessToken, 
                { 
                    maxAge: 7 * 24 * 60 * 60 * 1000, 
                    httpOnly: true, 
                    secure: process.env.ENVIRONMENT === 'production', 
                    sameSite: 'lax' 
                }
            );

            res.cookie("refreshToken", 
                refreshToken, 
                { 
                    maxAge: 7 * 24 * 60 * 60 * 1000, 
                    httpOnly: true, 
                    secure: process.env.ENVIRONMENT === 'production', 
                    sameSite: 'lax' 
                }
            );

            logger.info("Returning success response.");

            return res.status(HTTP_STATUS_CODE.SUCCESS).json(
                { 
                    status: HTTP_STATUS_MESSAGES.SUCCESS, 
                    data: { 
                        firstName: existingUser.firstName, 
                        lastName: existingUser.lastName, 
                        email: existingUser.email, 
                        avatar: existingUser.avatar, 
                        userName: existingUser.userName, 
                        newComer: false,
                        token: accessToken,
                        refreshToken: refreshToken
                    }
                }
            );

        }

    } catch (error) {
        logger.error("Error in googleAuthLogin", error.message || error);
        return res.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).json({ status: HTTP_STATUS_MESSAGES.SUCCESS, message: "Some error occurred while logging in with google", error: error.message })
    }
}

export const logoutUser = async (req: Request, res: Response): Promise<any> => {
    try {

        res.clearCookie("jwtToken");
        res.clearCookie("refreshToken");
        return res.status(HTTP_STATUS_CODE.SUCCESS).json({ status: HTTP_STATUS_MESSAGES.SUCCESS, message: "Logged out successfully!" });

    } catch (error) {
        logger.error(`Error in ${logoutUser.name}`, error);
        return res.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).json({ status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR, message: "Some error occurred while logging out user!" });
    }
}

/** UTILITY FUNCTIONS FOR FILE */

const generateTokens = (userId: string, role: string) => {

    const accessToken = jwt.sign({ userId, role }, process.env.JWT_SECRET, { expiresIn: "15m" });
    const refreshToken = jwt.sign({ userId, role }, process.env.JWT_REFRESH_SECRET, { expiresIn: "7d" });
    return { accessToken, refreshToken };
};

const generateUniqueUsername = async (firstName: string, lastName: string) : Promise<string> => {

    let baseUsername = `${firstName}${lastName ? lastName.charAt(0) : ""}`.toLowerCase();
    baseUsername = baseUsername.replace(/[^a-z0-9]/g, ""); // Remove special characters

    let username = baseUsername;

    while (await userModel.exists({ userName: username })) {
        username = `${baseUsername}${Math.floor(1000 + Math.random() * 9000)}`; // Add a random 4-digit number
    }

    return username;
};