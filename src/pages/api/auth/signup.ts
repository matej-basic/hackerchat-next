import type { NextApiResponse } from 'next';
import ExtendedNextApiRequest from '../../../types/ExtendedNextApiRequest';
import { User } from '../../../models/user';
import dbConnect from '../../../lib/dbConnect';
import { UserFoundError } from '../../../types/UserFoundError';


export default async function (req: ExtendedNextApiRequest, res: NextApiResponse) {

    await dbConnect();

    const { username, password } = req.body;
    const existingUser = await User.findOne({ username })
    if (existingUser) { throw new UserFoundError('Username already taken') };

    const user = new User({ username, password });
    await user.save();

    console.log("Received user: " + user);
    res.status(200).send(user);
}