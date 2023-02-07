import React from 'react';
import { useState } from 'react';
import LoginForm from './LoginForm';
import SignupForm from './SignupForm';

const LoginSignupForm = (props: { onChange: (arg0: any) => void; }) => {

    const [toggleState, setToggleState] = useState(1);

    const toggleTab = (index: React.SetStateAction<number>) => {
        setToggleState(index);
    }

    return (
        <div className='login-box'>
            <div className='tab-btn'>
                <div className='login-tab' onClick={() => toggleTab(1)}>SIGN IN</div>
                <div className='register-tab' onClick={() => toggleTab(2)}>SIGN UP</div>
            </div>
            {toggleState === 1 ? (<LoginForm onChange={value => props.onChange(value)} />) : (<SignupForm onChange={(value: any) => props.onChange(value)} />)}
        </div>
    )
}

export default LoginSignupForm