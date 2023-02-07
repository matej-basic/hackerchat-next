import { NextApiRequest, NextApiResponse } from "next";

export default function (req: NextApiRequest, res: NextApiResponse) {
    res.setHeader('Set-Cookie', 'hackerchat-jwt=null; Max-Age=0');

    res.status(200).send(({ "Result": "Log out successful" }));
}