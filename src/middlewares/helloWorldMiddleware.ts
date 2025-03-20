import { NextFunction, Request, Response } from "express";
import logger from "../utils/logger";
import { HTTP_STATUS_MESSAGES, HTTP_STATUS_CODE } from "../utils/httpStatus";

/**
 * Function to get the idea about middleware only
 * @param req Request
 * @param res Response
 * @param next NextFunction
 * @returns Redirect to the helloWorldController for further execution if all things are good
 */

const helloWorldMiddleware = async (req: Request, res: Response, next: NextFunction): Promise<any> => {
    try {
        logger.info("Running helloworldMiddleware");
        return next();
    } catch (error) {
        logger.error("Error in helloWorldMiddleware", error);
        return res.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).json({ status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR, message: "Something went wrong. Please contact admin!" })
    }
}

export default helloWorldMiddleware;