import { NextApiResponse } from "next";
import { serialize } from "cookie";

function setCookie(res: NextApiResponse, name: string, value: string) {
    res.setHeader('Set-Cookie', serialize(name, value, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        path: '/',
    }))
}

export default setCookie;