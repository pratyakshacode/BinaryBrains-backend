import mongoose from "mongoose";
import logger from "../utils/logger";

export const connectDatabase = async () => {
    try {
        logger.info("Connecting To MongoDB Database.");
        await mongoose.connect(process.env.MONGO_DB_URI)
        logger.info("MongoDB Connected.")
    } catch (error) {
        logger.error("Error while connecting to MongoDB.", error);
    }
}