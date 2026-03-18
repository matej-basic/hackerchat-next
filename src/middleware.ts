import { NextRequest, NextResponse } from "next/server";

export default function middleware(req: NextRequest) {
    return NextResponse.next();
}

export const config = {
    matcher: [
        '/(api/auth.*)'
    ],
}
