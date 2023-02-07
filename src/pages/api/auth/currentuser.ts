import { NextApiRequest, NextApiResponse } from "next";
import jwt from 'jsonwebtoken';
import dbConnect from "../../../lib/dbConnect";
import { User } from "../../../models/user";

export default async function (req: NextApiRequest, res: NextApiResponse) {
    const cookies = req.cookies;
    const token = cookies["hackerchat-jwt"]

    if (token === undefined) {
        res.status(200).send({ username: null })
        return
    }

    const username = jwt.verify(token, process.env.JWT_KEY)
    await dbConnect()
    const user = await User.findOne(username)

    res.status(200).send({ username: user["username"] });
}