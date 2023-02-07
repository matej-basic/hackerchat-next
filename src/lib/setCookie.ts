import { NextApiResponse } from "next";
import { serialize } from "cookie";

function setCookie(res: NextApiResponse, name: String, value: unknown) {
    res.setHeader('Set-Cookie', serialize(name, value))
}

export default setCookie;