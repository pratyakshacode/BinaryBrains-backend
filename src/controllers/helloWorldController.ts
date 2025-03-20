import { Request, Response } from 'express';
import { HTTP_STATUS_MESSAGES, HTTP_STATUS_CODE } from '../utils/httpStatus';
import logger from '../utils/logger';

/**
 * Dummy function to check for the implementation of the other functions in the application
 * @param req Request
 * @param res Response
 * @returns Promise<Request<any>>
 */

export const helloWorldController = async (req: Request, res: Response): Promise<any> => {
    try {
        logger.info("Running the hello world controller successfully!");
        return res.status(HTTP_STATUS_CODE.SUCCESS).json({ status: HTTP_STATUS_MESSAGES.SUCCESS, message: "Hello world router is running fine!" });
    } catch (error) {
        logger.error("ERror in helloWorldController", error);
        return res.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).json({ status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR, message: "Something went wrong. Please contact admin!" });
    }
}