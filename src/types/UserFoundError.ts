import { CustomError } from "./CustomError";

export class UserFoundError extends CustomError {
    statusCode = 400;

    constructor(public message: string) {
        super(message);

        Object.setPrototypeOf(this, UserFoundError.prototype);
    }

    serializeErrors() {
        return [{ message: this.message }];
    }
}