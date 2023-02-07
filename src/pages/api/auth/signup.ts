import type { NextApiRequest, NextApiResponse } from 'next';
import { User } from '../../../models/user';
import dbConnect from '../../../lib/dbConnect';
import jwt from 'jsonwebtoken';
import setCookie from '../../../lib/setCookie';


export default async function (req: NextApiRequest, res: NextApiResponse) {

    await dbConnect();

    const { username, password } = req.body;
    const existingUser = await User.findOne({ username })
    if (existingUser) { res.status(400).send("Username already taken"); return };

    const user = new User({ username, password })
    await user.save();

    const userJWT = jwt.sign({
        id: user.id,
        username: user.email
    }, process.env.JWT_KEY!)

    setCookie(res, "hackerchat-jwt", userJWT);

    res.status(200).send(user);
}