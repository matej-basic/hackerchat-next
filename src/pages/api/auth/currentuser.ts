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

    let payload: { id: string; username: string };
    try {
        payload = jwt.verify(token, process.env.JWT_KEY!) as typeof payload;
    } catch {
        res.status(200).send({ username: null });
        return;
    }

    await dbConnect()
    const user = await User.findOne({ username: payload.username })
    if (!user) {
        res.status(200).send({ username: null });
        return;
    }

    res.status(200).send({ username: user.username });
}