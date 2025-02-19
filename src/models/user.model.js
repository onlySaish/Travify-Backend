import mongoose, {Schema} from "mongoose";
import bcrypt from 'bcrypt'
// import jwt from 'jsonwebtoken'
// import mongooseAggregatePaginate from 'mongoose-aggregate-paginate-v2'
// import mongoosePaginate from 'mongoose-aggregate-paginate-v2'

const userSchema = new Schema(
    {
        phoneNumber: {
            type: String,
            required: true,
            unique: true,
            trim: true,
            index: true
        },
        email: {
            type: String,
            required: true,
            unique: true,
            lowercase: true,
            trim: true
        },
        password: {
            type: String,
            required: [true, "Password is Required"],
        },
        fullName: {
            type: String,
            required: true,
            trim: true,
            index: true
        },
        refreshToken: {
            type: String,
        }
    }
,{timestamps:true});

userSchema.pre("save", async function (next) {
    if (!this.isModified("password")) return

    this.password = await bcrypt.hash(this.password, 10);
    next();
})

// userSchema.methods.isPasswordCorrect = async function (password) {
//     return await bcrypt.compare(password,this.password)
// }

// userSchema.methods.generateAccessToken = function() {
//     return jwt.sign(
//         {
//             _id: this._id,
//             email: this.email,
//             username: this.username,
//             fullName: this.fullName
//         },
//         process.env.ACCESS_TOKEN_SECRET,
//         {
//             expiresIn: process.env.ACCESS_TOKEN_EXPIRY
//         }
//     )
// }

// userSchema.methods.generateRefreshToken = function() {
//     return jwt.sign(
//         {
//             _id: this._id,
//         },
//         process.env.REFRESH_TOKEN_SECRET,
//         {
//             expiresIn: process.env.REFRESH_TOKEN_EXPIRY
//         }
//     )
// }

// userSchema.plugin(mongooseAggregatePaginate,mongoosePaginate)

export const User = mongoose.model("User",userSchema);