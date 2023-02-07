import { NextApiRequest, NextApiResponse } from "next";
import dbConnect from "../../../lib/dbConnect";
import { User } from "../../../models/user";
import { Password } from "../../../services/password";
import jwt from 'jsonwebtoken'
import setCookie from "../../../lib/setCookie";

export default async function (req: NextApiRequest, res: NextApiResponse) {
    await dbConnect();
    const { username, password } = req.body;

    const existingUser = await User.findOne({ username });
    if (!existingUser) {
        res.status(400).send({ "Result": "Invalid credentials" });
        return;
    }

    const passwordsMatch = await Password.compare(existingUser.password, password);
    if (!passwordsMatch) {
        res.status(400).send({ "Result": "Invalid credentials" });
        return;
    }

    const userJWT = jwt.sign({
        id: existingUser.id,
        username: existingUser.email
    }, process.env.JWT_KEY!)

    setCookie(res, "hackerchat-jwt", userJWT);
    res.status(200).send({ "Result": "Sign in successful" })

}