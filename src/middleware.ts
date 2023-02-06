import { NextRequest, NextResponse } from "next/server";
import { UserType } from "./types/user";

export default async function middlware(req: NextRequest) {
    const path = req.nextUrl.pathname;
    const body = await req.json()

    if (!userTypeGuard(body)) {
        const response = NextResponse.redirect(new URL('/', req.url))
        return response;
    }

    const response = NextResponse.next();
    return response;
}

export const config = {
    matcher: [
        '/(api/auth.*)'
    ],
}

function userTypeGuard(requestBody: UserType) {

    if (typeof requestBody.username != "string" || typeof requestBody.password != "string") {
        return false
    }

    return true;
}