import { NextApiRequest, NextApiResponse } from "next";
import { serialize } from "cookie";

export default function (req: NextApiRequest, res: NextApiResponse) {
    res.setHeader('Set-Cookie', serialize('hackerchat-jwt', '', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        path: '/',
        maxAge: 0,
    }));

    res.status(200).send(({ "Result": "Log out successful" }));
}