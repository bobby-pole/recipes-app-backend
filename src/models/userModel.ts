import mongoose, { Document, Schema } from "mongoose";
import bcrypt from "bcrypt";

interface UserDocument extends Document {
  email: string;
  password: string;
  name: string | null;
  role: "user" | "admin";
  verifu: boolean;
  verificationToken?: string;
  isModified: (field: string) => boolean;
}

const userSchema = new Schema({
  email: {
    type: String,
    required: [true, "Email is required"],
    unique: true,
  },
  password: {
    type: String,
    trim: true,
    required: [true, "Password is required"],
  },
  name: {
    type: String,
    default: null,
    required: [true, "Name is required"],
  },
  role: {
    type: String,
    enum: {
      values: ["user", "admin"],
      message: "The role must be either user or admin",
    },
    default: "user",
  },
  verifu: {
    type: Boolean,
    default: false,
  },
  verificationToken: {
    type: String,
  },
});

userSchema.pre("save", async function (this: UserDocument, next) {
  if (!this.isModified("password")) return next();

  this.password = await bcrypt.hash(this.password, 12);
  next();
});

userSchema.pre(/^find/, function (this: any, next) {
  this.select("-password -verify -verifi");
  next();
});

userSchema.methods.isCorrectPassword = async function (
  passwordToCheck: string,
  userPassword: string
): Promise<boolean> {
  return await bcrypt.compare(passwordToCheck, userPassword);
};

const UserModel = mongoose.model<UserDocument>("User", userSchema);

export default UserModel;
