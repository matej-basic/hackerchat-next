import { NextApiRequest } from 'next'
import type { UserType } from './user'

export default interface ExtendedNextApiRequest extends NextApiRequest {
    body: UserType
}