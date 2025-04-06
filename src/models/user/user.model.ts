import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    firstName: {
        type: String,
        required: true,
        trim: true
    },
    lastName: {
        type: String,
        trim: true
    },
    userName: {
        type: String,
        required: true,
        unique: true, 
        trim: true
    },
    password: {
        type: String,
        required: true,
    },
    avatar: {
        type: String,
        default: ""
    },
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    phoneNumber: {
        type: String,
        default: "",
        match: [/^\d{10}$/, "Invalid phone number"]
    },
    college: {
        type: String,
        default: ""
    },
    role: {
        type: String,
        required: true,
        enum: ['admin', 'student', 'creator']
    },
    city: {
        type: String,
        default: ""
    },
    refreshToken: {
        type: String
    },
    googleId: {
        type: String,
        default: ""
    }
}, { timestamps: true });

export default mongoose.model("User", userSchema);
