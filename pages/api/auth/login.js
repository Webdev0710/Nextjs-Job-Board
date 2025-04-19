import ConnectDB from '@/DB/connectDB';
import User from '@/models/User';
import Joi from 'joi';
import { compare } from 'bcryptjs';
import jwt from 'jsonwebtoken';


const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required(),
});




export default async (req, res) => {

    res.setHeader('Access-Control-Allow-Credentials', true);
    res.setHeader(
        'Access-Control-Allow-Origin',
        'https://nextjs-job-board-ashy.vercel.app/'
    );
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
    res.setHeader(
        'Access-Control-Allow-Headers',
        'X-CSRF-Token, X-Requested-With, Accept, Content-Type, Authorization'
    );

    if (req.method === 'OPTIONS') {
        return res.status(200).end(); // 🛑 Stop here for preflight requests
    }

    // ✅ Ensure POST method only
    if (req.method !== 'POST') {
        return res.status(405).json({ success: false, message: 'Method Not Allowed' });
    }

    await ConnectDB();

    const { email, password } = req.body;
    const { error } = schema.validate({ email, password });

    if (error) return res.status(401).json({ success: false, message: error.details[0].message.replace(/['"]+/g, '') });

    try {
        const checkUser = await User.findOne({ email });
        if (!checkUser) {
          return res.status(401).json({ success: false, message: 'Account not Found' });
        }
    
        const isMatch = await compare(password, checkUser.password);
        if (!isMatch) {
          return res.status(401).json({ success: false, message: 'Incorrect Password' });
        }
    
        const token = jwt.sign(
          { id: checkUser._id, email: checkUser.email },
          process.env.JWT_SECREAT,
          { expiresIn: '1d' }
        );
    
        const finalData = { token, user: checkUser };
    
        return res.status(200).json({
          success: true,
          message: 'Login Successful',
          finalData,
        });
      } catch (err) {
        console.error('Error in login (server):', err);
        return res.status(500).json({
          success: false,
          message: 'Something Went Wrong, Please Retry Later!',
        });
      }
}
